use crate::AsyncReadWrite;
use crate::proxy::padding::PaddingFactory;
use crate::proxy::session::Stream;
use crate::proxy::session::frame::*;
use crate::util::string_map::{StringMap, StringMapExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Duration;

type FrameWrite = (Frame, Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>);

fn spawn_writer_task(
    mut writer: tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
    mut rx: Receiver<FrameWrite>,
    padding: Arc<RwLock<PaddingFactory>>,
    send_padding: Arc<Mutex<bool>>,
    buffering: Arc<Mutex<bool>>,
    buffer: Arc<Mutex<Vec<u8>>>,
    pkt_counter: Arc<Mutex<u32>>,
) {
    tokio::spawn(async move {
        while let Some((frame, ack)) = rx.recv().await {
            let res = async {
                write_conn(
                    &mut writer,
                    frame.to_bytes().to_vec(),
                    &padding,
                    &send_padding,
                    &buffering,
                    &buffer,
                    &pkt_counter,
                )
                .await?;
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

async fn write_conn(
    writer: &mut tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
    mut bytes: Vec<u8>,
    padding: &Arc<RwLock<PaddingFactory>>,
    send_padding: &Arc<Mutex<bool>>,
    buffering: &Arc<Mutex<bool>>,
    buffer: &Arc<Mutex<Vec<u8>>>,
    pkt_counter: &Arc<Mutex<u32>>,
) -> std::io::Result<usize> {
    if *buffering.lock().await {
        buffer.lock().await.extend_from_slice(&bytes);
        return Ok(bytes.len());
    }

    {
        let mut pending = buffer.lock().await;
        if !pending.is_empty() {
            let mut combined = Vec::with_capacity(pending.len() + bytes.len());
            combined.extend_from_slice(&pending);
            combined.extend_from_slice(&bytes);
            pending.clear();
            bytes = combined;
        }
    }

    let payload_len = bytes.len();

    if *send_padding.lock().await {
        let pkt = {
            let mut counter = pkt_counter.lock().await;
            *counter += 1;
            *counter
        };

        let padding_factory = padding.read().await.clone();
        if pkt < padding_factory.stop() {
            for spec in padding_factory.generate_record_payload_sizes(pkt) {
                let remain_payload_len = bytes.len();

                if spec == crate::proxy::padding::CHECK_MARK {
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
            *send_padding.lock().await = false;
        }
    }

    writer.write_all(&bytes).await?;
    Ok(payload_len)
}

pub struct Session {
    #[allow(clippy::type_complexity)]
    reader: Arc<tokio::sync::Mutex<tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>>>,
    streams: Arc<Mutex<HashMap<u32, Arc<Stream>>>>,
    stream_id: Arc<Mutex<u32>>,
    closed: Arc<Mutex<bool>>,
    is_client: bool,
    peer_version: Arc<Mutex<u8>>,
    padding: Arc<RwLock<PaddingFactory>>,
    send_padding: Arc<Mutex<bool>>,
    buffering: Arc<Mutex<bool>>,
    buffer: Arc<Mutex<Vec<u8>>>,
    pkt_counter: Arc<Mutex<u32>>,
    received_settings_from_client: Arc<Mutex<bool>>,
    synack_timeout: Arc<Mutex<HashMap<u32, JoinHandle<()>>>>,
    idle_notify: Arc<tokio::sync::Notify>,
    #[allow(clippy::type_complexity)]
    on_new_stream: Option<Arc<Box<dyn Fn(Arc<Stream>) + Send + Sync>>>,
    frame_tx: Sender<(Frame, Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>)>,
}

impl Session {
    pub fn new_client(conn: Box<dyn AsyncReadWrite>, padding: Arc<RwLock<PaddingFactory>>) -> Self {
        let (reader, writer) = tokio::io::split(conn);
        let send_padding = Arc::new(Mutex::new(true));
        let buffering = Arc::new(Mutex::new(false));
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let pkt_counter = Arc::new(Mutex::new(0));
        let (tx, rx) = tokio::sync::mpsc::channel::<FrameWrite>(100);
        spawn_writer_task(
            writer,
            rx,
            padding.clone(),
            send_padding.clone(),
            buffering.clone(),
            buffer.clone(),
            pkt_counter.clone(),
        );

        Self {
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            streams: Arc::new(Mutex::new(HashMap::new())),
            stream_id: Arc::new(Mutex::new(0)),
            closed: Arc::new(Mutex::new(false)),
            is_client: true,
            peer_version: Arc::new(Mutex::new(0)),
            padding,
            send_padding,
            buffering,
            buffer,
            pkt_counter,
            received_settings_from_client: Arc::new(Mutex::new(false)),
            synack_timeout: Arc::new(Mutex::new(HashMap::new())),
            idle_notify: Arc::new(tokio::sync::Notify::new()),
            on_new_stream: None,
            frame_tx: tx,
        }
    }

    pub fn new_server(
        conn: Box<dyn AsyncReadWrite>,
        on_new_stream: Box<dyn Fn(Arc<Stream>) + Send + Sync>,
        padding: Arc<RwLock<PaddingFactory>>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(conn);
        let send_padding = Arc::new(Mutex::new(false));
        let buffering = Arc::new(Mutex::new(false));
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let pkt_counter = Arc::new(Mutex::new(0));
        let (tx, rx) = tokio::sync::mpsc::channel::<FrameWrite>(100);
        spawn_writer_task(
            writer,
            rx,
            padding.clone(),
            send_padding.clone(),
            buffering.clone(),
            buffer.clone(),
            pkt_counter.clone(),
        );

        Self {
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            streams: Arc::new(Mutex::new(HashMap::new())),
            stream_id: Arc::new(Mutex::new(0)),
            closed: Arc::new(Mutex::new(false)),
            is_client: false,
            peer_version: Arc::new(Mutex::new(0)),
            padding,
            send_padding,
            buffering,
            buffer,
            pkt_counter,
            received_settings_from_client: Arc::new(Mutex::new(false)),
            synack_timeout: Arc::new(Mutex::new(HashMap::new())),
            idle_notify: Arc::new(tokio::sync::Notify::new()),
            on_new_stream: Some(Arc::new(on_new_stream)),
            frame_tx: tx,
        }
    }

    pub async fn run(&self) -> std::io::Result<()> {
        if self.is_client {
            self.send_settings().await?;
        }

        let result = self.recv_loop().await;
        let _ = self.close().await; // Ensure session is marked closed on exit
        result
    }

    async fn send_settings(&self) -> std::io::Result<()> {
        let mut settings = StringMap::new();
        settings.insert("v".to_string(), "2".to_string());
        settings.insert("client".to_string(), crate::PROGRAM_VERSION_NAME.to_string());

        settings.insert("padding-md5".to_string(), self.padding.read().await.md5().to_string());

        {
            let mut buffering = self.buffering.lock().await;
            *buffering = true;
        }

        let frame = Frame::with_data(CMD_SETTINGS, 0, settings.to_bytes().into());
        self.write_frame(frame).await?;

        Ok(())
    }

    async fn write_alert_and_fail(&self, message: &str) -> std::io::Result<()> {
        let frame = Frame::with_data(CMD_ALERT, 0, bytes::Bytes::copy_from_slice(message.as_bytes()));
        let _ = self.write_frame_sync(frame).await;
        Err(std::io::Error::other(message.to_string()))
    }

    async fn cancel_synack_timeout(&self, sid: u32) {
        if let Some(handle) = self.synack_timeout.lock().await.remove(&sid) {
            handle.abort();
        }
    }

    async fn recv_loop(&self) -> std::io::Result<()> {
        let mut buf = vec![0u8; 4096];
        let mut temp_buf = Vec::new();

        loop {
            if *self.closed.lock().await {
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed"));
            }

            let n = {
                match self.reader.lock().await.read(&mut buf).await {
                    Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Connection closed")),
                    Ok(n) => n,
                    Err(e) => return Err(e),
                }
            };

            temp_buf.extend_from_slice(&buf[..n]);

            while let Some(frame) = Frame::from_bytes(&temp_buf) {
                let frame_len = crate::proxy::session::frame::HEADER_OVERHEAD_SIZE + frame.data.len();
                temp_buf.drain(0..frame_len);

                log::trace!(
                    "Session received frame: cmd={}, sid={}, len={}",
                    frame.cmd,
                    frame.sid,
                    frame.data.len()
                );
                self.handle_frame(frame.cmd, frame.sid, frame.data.to_vec()).await?;
            }
        }
    }

    async fn handle_frame(&self, cmd: u8, sid: u32, data: Vec<u8>) -> std::io::Result<()> {
        match cmd {
            CMD_PSH if !data.is_empty() => {
                let streams = self.streams.lock().await;
                if let Some(stream) = streams.get(&sid) {
                    // Use internal pipe writer to push data to stream reader
                    stream.push_data(&data).await?;
                }
            }
            CMD_SYN if !self.is_client => {
                if !*self.received_settings_from_client.lock().await {
                    return self.write_alert_and_fail("client did not send its settings").await;
                }

                let mut streams = self.streams.lock().await;
                if let std::collections::hash_map::Entry::Vacant(e) = streams.entry(sid) {
                    log::debug!("Session received SYN for stream {sid}");
                    let stream = Arc::new(Stream::new(
                        sid,
                        self.frame_tx.clone(),
                        self.peer_version.clone(),
                        Arc::downgrade(&self.streams),
                        Arc::downgrade(&self.idle_notify),
                    ));
                    e.insert(stream.clone());

                    if let Some(callback) = &self.on_new_stream {
                        callback(stream);
                    }
                }
            }
            CMD_FIN => {
                log::debug!("Session received FIN for stream {}", sid);
                let stream = {
                    let streams = self.streams.lock().await;
                    streams.get(&sid).cloned()
                };
                if let Some(stream) = stream {
                    stream.close_local_with_error(None).await?;
                }
            }
            CMD_SETTINGS if !self.is_client && !data.is_empty() => {
                let settings = StringMap::from_bytes(&data);
                *self.received_settings_from_client.lock().await = true;

                let padding = self.padding.read().await.clone();
                if settings.get("padding-md5").map(String::as_str) != Some(padding.md5()) {
                    let frame = Frame::with_data(CMD_UPDATE_PADDING_SCHEME, 0, bytes::Bytes::copy_from_slice(padding.raw_scheme()));
                    self.write_frame_sync(frame).await?;
                }

                if let Some(version) = settings.get("v").and_then(|v| v.parse::<u8>().ok())
                    && version >= 2
                {
                    *self.peer_version.lock().await = version;
                    let mut server_settings = StringMap::new();
                    server_settings.insert("v".to_string(), "2".to_string());
                    let frame = Frame::with_data(CMD_SERVER_SETTINGS, 0, server_settings.to_bytes().into());
                    self.write_frame_sync(frame).await?;
                }
            }
            CMD_ALERT => {
                if !data.is_empty() {
                    let message = String::from_utf8_lossy(&data);
                    log::error!("Alert from server: {}", message);
                }
                return Err(std::io::Error::other("Alert received"));
            }
            CMD_UPDATE_PADDING_SCHEME => {
                if !data.is_empty()
                    && self.is_client
                    && let Some(factory) = PaddingFactory::new(&data)
                {
                    *self.padding.write().await = factory;
                }
            }
            CMD_HEART_REQUEST => {
                let frame = Frame::new(CMD_HEART_RESPONSE, sid);
                let tx = self.frame_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = tx.send((frame, None)).await {
                        log::error!("Failed to send heartbeat response: {e}");
                    }
                });
            }
            CMD_HEART_RESPONSE => {
                // Handle heartbeat response
            }
            CMD_SERVER_SETTINGS if !data.is_empty() && self.is_client => {
                let settings = StringMap::from_bytes(&data);
                if let Some(version) = settings.get("v").and_then(|v| v.parse::<u8>().ok()) {
                    *self.peer_version.lock().await = version;
                }
            }
            CMD_SYNACK => {
                self.cancel_synack_timeout(sid).await;
                if !data.is_empty() {
                    let message = String::from_utf8_lossy(&data).to_string();
                    let stream = {
                        let streams = self.streams.lock().await;
                        streams.get(&sid).cloned()
                    };
                    if let Some(stream) = stream {
                        stream
                            .close_with_error(Some(std::io::Error::other(format!("remote: {message}"))))
                            .await?;
                    }
                }
            }
            _ => log::warn!("Session received unknown command: cmd={}, sid={}, len={}", cmd, sid, data.len()),
        }
        Ok(())
    }

    async fn _read_exact(&self, n: usize) -> std::io::Result<Vec<u8>> {
        let buffer = vec![0u8; n];
        Ok(buffer)
    }

    pub async fn write_frame(&self, frame: Frame) -> std::io::Result<usize> {
        let len = frame.data.len();
        log::debug!("Session sending frame: cmd={}, sid={}, len={}", frame.cmd, frame.sid, len);
        match self.frame_tx.send((frame, None)).await {
            Ok(_) => Ok(len),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
        }
    }

    pub async fn write_frame_sync(&self, frame: Frame) -> std::io::Result<usize> {
        let len = frame.data.len();
        log::debug!("Session sending frame sync: cmd={}, sid={}, len={}", frame.cmd, frame.sid, len);
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();

        match self.frame_tx.send((frame, Some(ack_tx))).await {
            Ok(_) => match ack_rx.await {
                Ok(res) => res.map(|_| len),
                Err(_) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Writer dropped")),
            },
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
        }
    }

    pub async fn open_stream(&self) -> std::io::Result<Arc<Stream>> {
        let id = {
            let mut stream_id = self.stream_id.lock().await;
            *stream_id += 1;
            *stream_id
        };

        log::debug!("Session opening new stream {id}");
        let stream = Arc::new(Stream::new(
            id,
            self.frame_tx.clone(),
            self.peer_version.clone(),
            Arc::downgrade(&self.streams),
            Arc::downgrade(&self.idle_notify),
        ));
        self.streams.lock().await.insert(id, stream.clone());

        if id >= 2 && self.peer_version().await >= 2 {
            let session = self.clone();
            let handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let _ = session.close().await;
            });
            self.synack_timeout.lock().await.insert(id, handle);
        }

        let frame = Frame::new(CMD_SYN, id);
        if let Err(err) = self.write_frame_sync(frame).await {
            self.cancel_synack_timeout(id).await;
            stream.close_local_with_error(Some(std::io::Error::other(err.to_string()))).await?;
            return Err(err);
        }

        let mut buffering = self.buffering.lock().await;
        *buffering = false;

        Ok(stream)
    }

    pub async fn close(&self) -> std::io::Result<()> {
        {
            let mut closed = self.closed.lock().await;
            if *closed {
                return Ok(());
            }
            *closed = true;
        }

        let timeouts = {
            let mut timeouts = self.synack_timeout.lock().await;
            timeouts.drain().map(|(_, handle)| handle).collect::<Vec<_>>()
        };
        for timeout in timeouts {
            timeout.abort();
        }

        let streams = {
            let streams = self.streams.lock().await;
            streams.values().cloned().collect::<Vec<_>>()
        };
        for stream in streams {
            let _ = stream.close_local_with_error(None).await;
        }

        Ok(())
    }

    pub async fn is_closed(&self) -> bool {
        *self.closed.lock().await || self.frame_tx.is_closed()
    }

    pub async fn peer_version(&self) -> u8 {
        *self.peer_version.lock().await
    }

    pub async fn wait_for_idle(&self) {
        self.idle_notify.notified().await;
    }

    pub async fn stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            streams: self.streams.clone(),
            stream_id: self.stream_id.clone(),
            closed: self.closed.clone(),
            is_client: self.is_client,
            peer_version: self.peer_version.clone(),
            padding: self.padding.clone(),
            send_padding: self.send_padding.clone(),
            buffering: self.buffering.clone(),
            buffer: self.buffer.clone(),
            pkt_counter: self.pkt_counter.clone(),
            received_settings_from_client: self.received_settings_from_client.clone(),
            synack_timeout: self.synack_timeout.clone(),
            idle_notify: self.idle_notify.clone(),
            on_new_stream: self.on_new_stream.clone(),
            frame_tx: self.frame_tx.clone(),
        }
    }
}
