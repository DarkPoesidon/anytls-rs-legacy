pub mod client;
pub mod frame;
pub mod padding;
pub mod string_map;

use crate::AsyncReadWrite;
use crate::proxy::session::{Session, Stream};
use async_trait::async_trait;
use padding::{CHECK_MARK, PaddingFactory};
use std::collections::HashMap;
use std::sync::Arc;
use string_map::{StringMap, StringMapExt};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Duration;

pub(crate) use frame::*;

pub(crate) type FrameWrite = (Frame, Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>);

pub(crate) struct AnyTlsState {
    pub(crate) padding: Arc<RwLock<PaddingFactory>>,
    pub(crate) peer_version: Arc<Mutex<u8>>,
    pub(crate) send_padding: Arc<Mutex<bool>>,
    pub(crate) buffering: Arc<Mutex<bool>>,
    pub(crate) buffer: Arc<Mutex<Vec<u8>>>,
    pub(crate) pkt_counter: Arc<Mutex<u32>>,
    pub(crate) received_settings_from_client: Arc<Mutex<bool>>,
    pub(crate) synack_timeout: Arc<Mutex<HashMap<u32, JoinHandle<()>>>>,
}

impl AnyTlsState {
    pub(crate) fn new(padding: Arc<RwLock<PaddingFactory>>, is_client: bool) -> Arc<Self> {
        Arc::new(Self {
            padding,
            peer_version: Arc::new(Mutex::new(0)),
            send_padding: Arc::new(Mutex::new(is_client)),
            buffering: Arc::new(Mutex::new(false)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            pkt_counter: Arc::new(Mutex::new(0)),
            received_settings_from_client: Arc::new(Mutex::new(false)),
            synack_timeout: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

pub(crate) fn new_client_session(conn: Box<dyn AsyncReadWrite>, padding: Arc<RwLock<PaddingFactory>>) -> Session {
    let protocol: Arc<dyn Protocol> = Arc::new(AnyTlsProtocol);
    let protocol_state = AnyTlsState::new(padding, true);
    Session::new_with_protocol(conn, true, None, protocol, protocol_state)
}

pub(crate) fn new_server_session(
    conn: Box<dyn AsyncReadWrite>,
    on_new_stream: Box<dyn Fn(Arc<Stream>) + Send + Sync>,
    padding: Arc<RwLock<PaddingFactory>>,
) -> Session {
    let protocol: Arc<dyn Protocol> = Arc::new(AnyTlsProtocol);
    let protocol_state = AnyTlsState::new(padding, false);
    Session::new_with_protocol(conn, false, Some(on_new_stream), protocol, protocol_state)
}

#[async_trait]
pub(crate) trait StreamProtocolHooks: Send + Sync {
    async fn handshake_failure(&self, stream_id: u32, error: &str) -> std::io::Result<()>;

    async fn handshake_success(&self, stream_id: u32) -> std::io::Result<()>;
}

#[async_trait]
pub(crate) trait Protocol: Send + Sync {
    fn spawn_writer_task(&self, writer: tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>, rx: Receiver<FrameWrite>, state: Arc<AnyTlsState>);

    fn make_stream_protocol_hooks(&self, frame_tx: Sender<FrameWrite>, state: Arc<AnyTlsState>) -> Arc<dyn StreamProtocolHooks>;

    async fn on_session_start(&self, session: &Session) -> std::io::Result<()>;

    async fn handle_frame(&self, session: &Session, frame: Frame) -> std::io::Result<()>;

    async fn open_stream(&self, session: &Session) -> std::io::Result<Arc<Stream>>;
}

#[derive(Default)]
pub(crate) struct AnyTlsProtocol;

struct AnyTlsStreamProtocolHooks {
    frame_tx: Sender<FrameWrite>,
    peer_version: Arc<Mutex<u8>>,
    reported: Arc<Mutex<bool>>,
}

#[async_trait]
impl StreamProtocolHooks for AnyTlsStreamProtocolHooks {
    async fn handshake_failure(&self, stream_id: u32, error: &str) -> std::io::Result<()> {
        {
            let mut reported = self.reported.lock().await;
            if *reported {
                return Ok(());
            }
            *reported = true;
        }

        if *self.peer_version.lock().await >= 2 {
            let frame = Frame::with_data(CMD_SYNACK, stream_id, bytes::Bytes::copy_from_slice(error.as_bytes()));
            match self.frame_tx.send((frame, None)).await {
                Ok(_) => {}
                Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
            }
        }

        Ok(())
    }

    async fn handshake_success(&self, stream_id: u32) -> std::io::Result<()> {
        {
            let mut reported = self.reported.lock().await;
            if *reported {
                return Ok(());
            }
            *reported = true;
        }

        if *self.peer_version.lock().await >= 2 {
            let frame = Frame::new(CMD_SYNACK, stream_id);
            match self.frame_tx.send((frame, None)).await {
                Ok(_) => {}
                Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
            }
        }

        Ok(())
    }
}

impl AnyTlsProtocol {
    async fn write_alert_and_fail(&self, session: &Session, message: &str) -> std::io::Result<()> {
        let frame = Frame::with_data(CMD_ALERT, 0, bytes::Bytes::copy_from_slice(message.as_bytes()));
        let _ = session.write_frame_sync(frame).await;
        Err(std::io::Error::other(message.to_string()))
    }

    async fn write_conn(
        writer: &mut tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
        mut bytes: Vec<u8>,
        state: &Arc<AnyTlsState>,
    ) -> std::io::Result<usize> {
        if *state.buffering.lock().await {
            state.buffer.lock().await.extend_from_slice(&bytes);
            return Ok(bytes.len());
        }

        {
            let mut pending = state.buffer.lock().await;
            if !pending.is_empty() {
                let mut combined = Vec::with_capacity(pending.len() + bytes.len());
                combined.extend_from_slice(&pending);
                combined.extend_from_slice(&bytes);
                pending.clear();
                bytes = combined;
            }
        }

        let payload_len = bytes.len();

        if *state.send_padding.lock().await {
            let pkt = {
                let mut counter = state.pkt_counter.lock().await;
                *counter += 1;
                *counter
            };

            let padding_factory = state.padding.read().await.clone();
            if pkt < padding_factory.stop() {
                for spec in padding_factory.generate_record_payload_sizes(pkt) {
                    let remain_payload_len = bytes.len();

                    if spec == CHECK_MARK {
                        if remain_payload_len == 0 {
                            break;
                        }
                        continue;
                    }

                    let frame_len = spec.max(0) as usize;
                    if remain_payload_len > frame_len {
                        writer.write_all(&bytes[..frame_len]).await?;
                        bytes.drain(0..frame_len);
                    } else if remain_payload_len > 0 {
                        let padding_len = frame_len.saturating_sub(remain_payload_len).saturating_sub(HEADER_OVERHEAD_SIZE);
                        if padding_len > 0 {
                            let mut padding_frame = vec![0u8; HEADER_OVERHEAD_SIZE + padding_len];
                            padding_frame[0] = CMD_WASTE;
                            padding_frame[5..7].copy_from_slice(&(padding_len as u16).to_be_bytes());
                            bytes.extend_from_slice(&padding_frame);
                        }
                        writer.write_all(&bytes).await?;
                        bytes.clear();
                    } else {
                        let mut padding_frame = vec![0u8; HEADER_OVERHEAD_SIZE + frame_len];
                        padding_frame[0] = CMD_WASTE;
                        padding_frame[5..7].copy_from_slice(&(frame_len as u16).to_be_bytes());
                        writer.write_all(&padding_frame).await?;
                    }
                }

                if bytes.is_empty() {
                    return Ok(payload_len);
                }
            } else {
                *state.send_padding.lock().await = false;
            }
        }

        writer.write_all(&bytes).await?;
        Ok(payload_len)
    }

    async fn send_settings(&self, session: &Session) -> std::io::Result<()> {
        let mut settings = StringMap::new();
        settings.insert("v".to_string(), "2".to_string());
        settings.insert("client".to_string(), crate::PROGRAM_VERSION_NAME.to_string());
        settings.insert(
            "padding-md5".to_string(),
            session.protocol_state.padding.read().await.md5().to_string(),
        );

        {
            let mut buffering = session.protocol_state.buffering.lock().await;
            *buffering = true;
        }

        let frame = Frame::with_data(CMD_SETTINGS, 0, settings.to_bytes().into());
        session.write_frame(frame).await?;
        Ok(())
    }

    async fn handle_push(&self, session: &Session, sid: u32, data: &[u8]) -> std::io::Result<()> {
        let streams = session.streams.lock().await;
        if let Some(stream) = streams.get(&sid) {
            stream.push_data(data).await?;
        }
        Ok(())
    }

    async fn handle_syn(&self, session: &Session, sid: u32) -> std::io::Result<()> {
        if !*session.protocol_state.received_settings_from_client.lock().await {
            return self.write_alert_and_fail(session, "client did not send its settings").await;
        }

        let mut streams = session.streams.lock().await;
        if let std::collections::hash_map::Entry::Vacant(entry) = streams.entry(sid) {
            log::debug!("Session received SYN for stream {sid}");
            let stream = Arc::new(session.new_stream(sid));
            entry.insert(stream.clone());

            if let Some(callback) = &session.on_new_stream {
                callback(stream);
            }
        }

        Ok(())
    }

    async fn handle_fin(&self, session: &Session, sid: u32) -> std::io::Result<()> {
        log::debug!("Session received FIN for stream {}", sid);
        let stream = {
            let streams = session.streams.lock().await;
            streams.get(&sid).cloned()
        };
        if let Some(stream) = stream {
            stream.close_local_with_error(None).await?;
        }
        Ok(())
    }

    async fn handle_settings(&self, session: &Session, data: &[u8]) -> std::io::Result<()> {
        let settings = StringMap::from_bytes(data);
        *session.protocol_state.received_settings_from_client.lock().await = true;

        let padding = session.protocol_state.padding.read().await.clone();
        if settings.get("padding-md5").map(String::as_str) != Some(padding.md5()) {
            let frame = Frame::with_data(CMD_UPDATE_PADDING_SCHEME, 0, bytes::Bytes::copy_from_slice(padding.raw_scheme()));
            session.write_frame_sync(frame).await?;
        }

        if let Some(version) = settings.get("v").and_then(|v| v.parse::<u8>().ok())
            && version >= 2
        {
            *session.protocol_state.peer_version.lock().await = version;
            let mut server_settings = StringMap::new();
            server_settings.insert("v".to_string(), "2".to_string());
            let frame = Frame::with_data(CMD_SERVER_SETTINGS, 0, server_settings.to_bytes().into());
            session.write_frame_sync(frame).await?;
        }

        Ok(())
    }

    async fn handle_update_padding_scheme(&self, session: &Session, data: &[u8]) {
        if let Some(factory) = PaddingFactory::new(data) {
            *session.protocol_state.padding.write().await = factory;
        }
    }

    async fn handle_server_settings(&self, session: &Session, data: &[u8]) {
        let settings = StringMap::from_bytes(data);
        if let Some(version) = settings.get("v").and_then(|v| v.parse::<u8>().ok()) {
            *session.protocol_state.peer_version.lock().await = version;
        }
    }

    async fn handle_synack(&self, session: &Session, sid: u32, data: &[u8]) -> std::io::Result<()> {
        session.cancel_synack_timeout(sid).await;
        if !data.is_empty() {
            let message = String::from_utf8_lossy(data).to_string();
            let stream = {
                let streams = session.streams.lock().await;
                streams.get(&sid).cloned()
            };
            if let Some(stream) = stream {
                stream
                    .close_with_error(Some(std::io::Error::other(format!("remote: {message}"))))
                    .await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Protocol for AnyTlsProtocol {
    fn spawn_writer_task(
        &self,
        mut writer: tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
        mut rx: Receiver<FrameWrite>,
        state: Arc<AnyTlsState>,
    ) {
        tokio::spawn(async move {
            while let Some((frame, ack)) = rx.recv().await {
                let res = async {
                    Self::write_conn(&mut writer, frame.to_bytes().to_vec(), &state).await?;
                    writer.flush().await
                }
                .await;

                if let Some(ack_tx) = ack {
                    let _ = ack_tx.send(if res.is_ok() {
                        Ok(())
                    } else {
                        Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Write failed"))
                    });
                }

                if let Err(e) = res {
                    log::error!("Failed to write frame to peer: {e}");
                    break;
                }
            }
            log::debug!("Session writer task exiting (writer loop ended)");
        });
    }

    fn make_stream_protocol_hooks(&self, frame_tx: Sender<FrameWrite>, state: Arc<AnyTlsState>) -> Arc<dyn StreamProtocolHooks> {
        Arc::new(AnyTlsStreamProtocolHooks {
            frame_tx,
            peer_version: state.peer_version.clone(),
            reported: Arc::new(Mutex::new(false)),
        })
    }

    async fn on_session_start(&self, session: &Session) -> std::io::Result<()> {
        if session.is_client {
            self.send_settings(session).await?;
        }
        Ok(())
    }

    async fn handle_frame(&self, session: &Session, frame: Frame) -> std::io::Result<()> {
        match frame.cmd {
            CMD_PSH if !frame.data.is_empty() => self.handle_push(session, frame.sid, frame.data.as_ref()).await?,
            CMD_SYN if !session.is_client => self.handle_syn(session, frame.sid).await?,
            CMD_FIN => self.handle_fin(session, frame.sid).await?,
            CMD_SETTINGS if !session.is_client && !frame.data.is_empty() => self.handle_settings(session, frame.data.as_ref()).await?,
            CMD_ALERT => {
                if !frame.data.is_empty() {
                    let message = String::from_utf8_lossy(frame.data.as_ref());
                    log::error!("Alert from server: {}", message);
                }
                return Err(std::io::Error::other("Alert received"));
            }
            CMD_UPDATE_PADDING_SCHEME if !frame.data.is_empty() && session.is_client => {
                self.handle_update_padding_scheme(session, frame.data.as_ref()).await;
            }
            CMD_HEART_REQUEST => {
                let response = Frame::new(CMD_HEART_RESPONSE, frame.sid);
                let tx = session.frame_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = tx.send((response, None)).await {
                        log::error!("Failed to send heartbeat response: {e}");
                    }
                });
            }
            CMD_HEART_RESPONSE => {}
            CMD_SERVER_SETTINGS if !frame.data.is_empty() && session.is_client => {
                self.handle_server_settings(session, frame.data.as_ref()).await;
            }
            CMD_SYNACK => self.handle_synack(session, frame.sid, frame.data.as_ref()).await?,
            _ => log::warn!(
                "Session received unknown command: cmd={}, sid={}, len={}",
                frame.cmd,
                frame.sid,
                frame.data.len()
            ),
        }
        Ok(())
    }

    async fn open_stream(&self, session: &Session) -> std::io::Result<Arc<Stream>> {
        let id = {
            let mut stream_id = session.stream_id.lock().await;
            *stream_id += 1;
            *stream_id
        };

        log::debug!("Session opening new stream {id}");
        let stream = Arc::new(session.new_stream(id));
        session.streams.lock().await.insert(id, stream.clone());

        if id >= 2 && session.peer_version().await >= 2 {
            let session_clone = session.clone();
            let handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let _ = session_clone.close().await;
            });
            session.protocol_state.synack_timeout.lock().await.insert(id, handle);
        }

        let frame = Frame::new(CMD_SYN, id);
        if let Err(err) = session.write_frame_sync(frame).await {
            session.cancel_synack_timeout(id).await;
            stream.close_local_with_error(Some(std::io::Error::other(err.to_string()))).await?;
            return Err(err);
        }

        let mut buffering = session.protocol_state.buffering.lock().await;
        *buffering = false;

        Ok(stream)
    }
}
