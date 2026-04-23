use crate::AsyncReadWrite;
use crate::core::Engine;
use crate::core::ProtocolAction;
use crate::core::ProtocolHost;
use crate::core::State;
use crate::core::{CHECK_MARK, PaddingFactory};
use crate::core::{Command, Frame, HEADER_OVERHEAD_SIZE};
use crate::proxy::session::{Session, Stream};
use async_trait::async_trait;
use parking_lot::Mutex as BlockingMutex;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};

pub(crate) type FrameWrite = (Frame, Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>);

pub(crate) struct WriterRuntimeState {
    send_padding: Arc<Mutex<bool>>,
    buffering: Arc<Mutex<bool>>,
    buffer: Arc<Mutex<Vec<u8>>>,
    pkt_counter: Arc<Mutex<u32>>,
}

impl WriterRuntimeState {
    pub(crate) fn new(is_client: bool) -> Arc<Self> {
        Arc::new(Self {
            send_padding: Arc::new(Mutex::new(is_client)),
            buffering: Arc::new(Mutex::new(false)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            pkt_counter: Arc::new(Mutex::new(0)),
        })
    }

    pub(crate) async fn is_send_padding_enabled(&self) -> bool {
        *self.send_padding.lock().await
    }

    pub(crate) async fn disable_send_padding(&self) {
        *self.send_padding.lock().await = false;
    }

    pub(crate) async fn is_buffering(&self) -> bool {
        *self.buffering.lock().await
    }

    pub(crate) async fn set_buffering(&self, enabled: bool) {
        *self.buffering.lock().await = enabled;
    }

    pub(crate) async fn append_buffered_bytes(&self, bytes: &[u8]) {
        self.buffer.lock().await.extend_from_slice(bytes);
    }

    pub(crate) async fn take_buffered_bytes(&self) -> Vec<u8> {
        let mut pending = self.buffer.lock().await;
        std::mem::take(&mut *pending)
    }

    pub(crate) async fn next_packet_counter(&self) -> u32 {
        let mut counter = self.pkt_counter.lock().await;
        *counter += 1;
        *counter
    }
}

pub(crate) async fn new_client_session(conn: Box<dyn AsyncReadWrite>, padding: Arc<RwLock<PaddingFactory>>) -> Session {
    let protocol: Arc<dyn Protocol> = Arc::new(AnyTlsProtocol);
    let protocol_state = State::new(padding.read().await.clone());
    let writer_state = WriterRuntimeState::new(true);
    Session::new_with_protocol(conn, true, None, protocol, protocol_state, writer_state)
}

pub(crate) async fn new_server_session(
    conn: Box<dyn AsyncReadWrite>,
    on_new_stream: Box<dyn Fn(Arc<Stream>) + Send + Sync>,
    padding: Arc<RwLock<PaddingFactory>>,
) -> Session {
    let protocol: Arc<dyn Protocol> = Arc::new(AnyTlsProtocol);
    let protocol_state = State::new(padding.read().await.clone());
    let writer_state = WriterRuntimeState::new(false);
    Session::new_with_protocol(conn, false, Some(on_new_stream), protocol, protocol_state, writer_state)
}

#[async_trait]
pub(crate) trait StreamProtocolHooks: Send + Sync {
    async fn handshake_failure(&self, stream_id: u32, error: &str) -> std::io::Result<()>;

    async fn handshake_success(&self, stream_id: u32) -> std::io::Result<()>;
}

#[async_trait]
pub(crate) trait Protocol: Send + Sync {
    fn spawn_writer_task(
        &self,
        writer: tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
        rx: Receiver<FrameWrite>,
        state: Arc<State>,
        writer_state: Arc<WriterRuntimeState>,
    );

    fn make_stream_protocol_hooks(&self, frame_tx: Sender<FrameWrite>, state: Arc<State>) -> Arc<dyn StreamProtocolHooks>;

    async fn on_session_start(&self, host: &dyn ProtocolHost) -> std::io::Result<()>;

    async fn handle_frame(&self, host: &dyn ProtocolHost, frame: Frame) -> std::io::Result<()>;

    async fn open_stream(&self, host: &dyn ProtocolHost, sid: u32) -> std::io::Result<()>;
}

#[derive(Default)]
pub(crate) struct AnyTlsProtocol;

struct AnyTlsStreamProtocolHooks {
    frame_tx: Sender<FrameWrite>,
    peer_version: Arc<BlockingMutex<u8>>,
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

        if *self.peer_version.lock() >= 2 {
            let frame = Frame::with_data(Command::SynAck, stream_id, bytes::Bytes::copy_from_slice(error.as_bytes()));
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

        if *self.peer_version.lock() >= 2 {
            let frame = Frame::new(Command::SynAck, stream_id);
            match self.frame_tx.send((frame, None)).await {
                Ok(_) => {}
                Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
            }
        }

        Ok(())
    }
}

impl AnyTlsProtocol {
    async fn write_conn(
        writer: &mut tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
        mut bytes: Vec<u8>,
        state: &Arc<State>,
        writer_state: &Arc<WriterRuntimeState>,
    ) -> std::io::Result<usize> {
        if writer_state.is_buffering().await {
            writer_state.append_buffered_bytes(&bytes).await;
            return Ok(bytes.len());
        }

        {
            let pending = writer_state.take_buffered_bytes().await;
            if !pending.is_empty() {
                let mut combined = Vec::with_capacity(pending.len() + bytes.len());
                combined.extend_from_slice(&pending);
                combined.extend_from_slice(&bytes);
                bytes = combined;
            }
        }

        let payload_len = bytes.len();

        if writer_state.is_send_padding_enabled().await {
            let pkt = writer_state.next_packet_counter().await;

            let padding_factory = state.padding();
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
                            padding_frame[0] = Command::Waste.into();
                            padding_frame[5..7].copy_from_slice(&(padding_len as u16).to_be_bytes());
                            bytes.extend_from_slice(&padding_frame);
                        }
                        writer.write_all(&bytes).await?;
                        bytes.clear();
                    } else {
                        let mut padding_frame = vec![0u8; HEADER_OVERHEAD_SIZE + frame_len];
                        padding_frame[0] = Command::Waste.into();
                        padding_frame[5..7].copy_from_slice(&(frame_len as u16).to_be_bytes());
                        writer.write_all(&padding_frame).await?;
                    }
                }

                if bytes.is_empty() {
                    return Ok(payload_len);
                }
            } else {
                writer_state.disable_send_padding().await;
            }
        }

        writer.write_all(&bytes).await?;
        Ok(payload_len)
    }

    async fn apply_actions(&self, host: &dyn ProtocolHost, actions: Vec<ProtocolAction>) -> std::io::Result<()> {
        for action in actions {
            match action {
                ProtocolAction::SendFrame(frame) => {
                    host.send_frame(frame).await?;
                }
                ProtocolAction::SendFrameSync(frame) => {
                    host.send_frame_sync(frame).await?;
                }
                ProtocolAction::PushStreamData { sid, data } => {
                    host.push_stream_data(sid, data).await?;
                }
                ProtocolAction::EnsureIncomingStream { sid } => {
                    host.ensure_incoming_stream(sid).await?;
                }
                ProtocolAction::CloseLocalStream { sid } => {
                    host.close_local_stream(sid).await?;
                }
                ProtocolAction::CloseRemoteStream { sid, message } => {
                    host.close_remote_stream(sid, message).await?;
                }
                ProtocolAction::CancelSynAckTimeout { sid } => {
                    host.cancel_synack_timeout(sid).await;
                }
                ProtocolAction::ArmSynAckTimeout { sid, timeout } => {
                    host.arm_synack_timeout(sid, timeout).await;
                }
                ProtocolAction::ReleaseWriteBuffering => {
                    host.release_write_buffering().await;
                }
                ProtocolAction::AlertAndFail { message } => {
                    let frame = Frame::with_data(Command::Alert, 0, bytes::Bytes::copy_from_slice(message.as_bytes()));
                    let _ = host.send_frame_sync(frame).await;
                    return Err(std::io::Error::other(message));
                }
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
        state: Arc<State>,
        writer_state: Arc<WriterRuntimeState>,
    ) {
        tokio::spawn(async move {
            while let Some((frame, ack)) = rx.recv().await {
                let res = async {
                    Self::write_conn(&mut writer, frame.to_bytes().to_vec(), &state, &writer_state).await?;
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

                if let Err(error) = res {
                    log::error!("Failed to write frame to peer: {error}");
                    break;
                }
            }
            log::debug!("Session writer task exiting (writer loop ended)");
        });
    }

    fn make_stream_protocol_hooks(&self, frame_tx: Sender<FrameWrite>, state: Arc<State>) -> Arc<dyn StreamProtocolHooks> {
        Arc::new(AnyTlsStreamProtocolHooks {
            frame_tx,
            peer_version: state.peer_version_handle(),
            reported: Arc::new(Mutex::new(false)),
        })
    }

    async fn on_session_start(&self, host: &dyn ProtocolHost) -> std::io::Result<()> {
        let actions = Engine::on_session_start(&host.protocol_state(), host.is_client(), crate::PROGRAM_VERSION_NAME)?;
        self.apply_actions(host, actions).await
    }

    async fn handle_frame(&self, host: &dyn ProtocolHost, frame: Frame) -> std::io::Result<()> {
        let should_warn = matches!(frame.cmd, Command::Unknown(_));

        if frame.cmd == Command::Alert {
            if !frame.data.is_empty() {
                let message = String::from_utf8_lossy(frame.data.as_ref());
                log::error!("Alert from server: {}", message);
            }
            return Err(std::io::Error::other("Alert received"));
        }

        if should_warn {
            log::warn!(
                "Session received unexpected command: cmd={}, sid={}, len={}",
                frame.cmd,
                frame.sid,
                frame.data.len()
            );
        }

        let actions = Engine::on_frame(&host.protocol_state(), host.is_client(), &frame)?;
        self.apply_actions(host, actions).await
    }

    async fn open_stream(&self, host: &dyn ProtocolHost, sid: u32) -> std::io::Result<()> {
        log::debug!("Session opening new stream {sid}");

        let actions = Engine::on_open_stream(&host.protocol_state(), sid);
        self.apply_actions(host, actions).await
    }
}
