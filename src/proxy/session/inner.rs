use crate::proxy::padding::PaddingFactory;
use crate::proxy::session::Stream;
use crate::proxy::session::frame::*;
use crate::util::string_map::{StringMap, StringMapExt};
use crate::util::r#type::AsyncReadWrite;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, RwLock};

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
    idle_notify: Arc<tokio::sync::Notify>,
    #[allow(clippy::type_complexity)]
    on_new_stream: Option<Arc<Box<dyn Fn(Arc<Stream>) + Send + Sync>>>,
    frame_tx: Sender<Frame>,
}

impl Session {
    pub fn new_client(conn: Box<dyn AsyncReadWrite>, padding: Arc<RwLock<PaddingFactory>>) -> Self {
        let (reader, mut writer) = tokio::io::split(conn);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Frame>(100);

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            while let Some(frame) = rx.recv().await {
                let data = frame.to_bytes();
                if let Err(e) = writer.write_all(&data).await {
                    log::error!("Failed to write frame: {}", e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    log::error!("Failed to flush frame: {e}");
                    break;
                }
            }
        });

        Self {
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            streams: Arc::new(Mutex::new(HashMap::new())),
            stream_id: Arc::new(Mutex::new(0)),
            closed: Arc::new(Mutex::new(false)),
            is_client: true,
            peer_version: Arc::new(Mutex::new(0)),
            padding,
            send_padding: Arc::new(Mutex::new(true)),
            buffering: Arc::new(Mutex::new(false)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            pkt_counter: Arc::new(Mutex::new(0)),
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
        let (reader, mut writer) = tokio::io::split(conn);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Frame>(100);

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            while let Some(frame) = rx.recv().await {
                let data = frame.to_bytes();
                if let Err(e) = writer.write_all(&data).await {
                    log::error!("Failed to write frame: {}", e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    log::error!("Failed to flush frame: {e}");
                    break;
                }
            }
        });

        Self {
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            streams: Arc::new(Mutex::new(HashMap::new())),
            stream_id: Arc::new(Mutex::new(0)),
            closed: Arc::new(Mutex::new(false)),
            is_client: false,
            peer_version: Arc::new(Mutex::new(0)),
            padding,
            send_padding: Arc::new(Mutex::new(false)),
            buffering: Arc::new(Mutex::new(false)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            pkt_counter: Arc::new(Mutex::new(0)),
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

        let frame = Frame::with_data(CMD_SETTINGS, 0, settings.to_bytes().into());
        self.write_frame(frame).await?;

        let mut buffering = self.buffering.lock().await;
        *buffering = true;

        Ok(())
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
            CMD_PSH => {
                if !data.is_empty() {
                    let streams = self.streams.lock().await;
                    if let Some(stream) = streams.get(&sid) {
                        // Use internal pipe writer to push data to stream reader
                        stream.push_data(&data).await?;
                    }
                }
            }
            CMD_SYN => {
                if !self.is_client {
                    let mut streams = self.streams.lock().await;
                    if let std::collections::hash_map::Entry::Vacant(e) = streams.entry(sid) {
                        log::debug!("Session received SYN for stream {sid}");
                        let stream = Arc::new(Stream::new(sid, self.frame_tx.clone()));
                        e.insert(stream.clone());

                        if let Some(callback) = &self.on_new_stream {
                            callback(stream);
                        }
                    }
                }
            }
            CMD_FIN => {
                log::debug!("Session received FIN for stream {}", sid);
                let mut streams = self.streams.lock().await;
                if let Some(stream) = streams.remove(&sid) {
                    stream.close().await?;
                }
                if streams.is_empty() {
                    self.idle_notify.notify_waiters();
                }
            }
            CMD_SETTINGS => {
                if !self.is_client && !data.is_empty() {
                    let _settings = StringMap::from_bytes(&data);
                    // Handle settings
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
                if !data.is_empty() && self.is_client {
                    // Update padding scheme
                }
            }
            CMD_HEART_REQUEST => {
                let frame = Frame::new(CMD_HEART_RESPONSE, sid);
                let tx = self.frame_tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(frame).await;
                });
            }
            CMD_HEART_RESPONSE => {
                // Handle heartbeat response
            }
            CMD_SERVER_SETTINGS => {
                if !data.is_empty() && self.is_client {
                    let _settings = StringMap::from_bytes(&data);
                    // Handle server settings
                }
            }
            CMD_SYNACK => {
                // Handle SYNACK
            }
            _ => {
                // Unknown command
            }
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
        match self.frame_tx.send(frame).await {
            Ok(_) => Ok(len),
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
        let stream = Arc::new(Stream::new(id, self.frame_tx.clone()));

        let frame = Frame::new(CMD_SYN, id);
        self.write_frame(frame).await?;

        let mut streams = self.streams.lock().await;
        streams.insert(id, stream.clone());

        Ok(stream)
    }

    pub async fn stream_closed(&self, sid: u32) -> std::io::Result<()> {
        let frame = Frame::new(CMD_FIN, sid);
        self.write_frame(frame).await?;

        let mut streams = self.streams.lock().await;
        streams.remove(&sid);
        if streams.is_empty() {
            self.idle_notify.notify_waiters();
        }

        Ok(())
    }

    pub async fn close(&self) -> std::io::Result<()> {
        {
            let mut closed = self.closed.lock().await;
            if *closed {
                return Ok(());
            }
            *closed = true;
        }

        let streams = self.streams.lock().await;
        for stream in streams.values() {
            let _ = stream.close().await;
        }

        Ok(())
    }

    pub async fn is_closed(&self) -> bool {
        *self.closed.lock().await
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
            idle_notify: self.idle_notify.clone(),
            on_new_stream: self.on_new_stream.clone(),
            frame_tx: self.frame_tx.clone(),
        }
    }
}
