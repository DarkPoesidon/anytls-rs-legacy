use crate::AsyncReadWrite;
use crate::protocol::{AnyTlsState, Frame, FrameWrite, HEADER_OVERHEAD_SIZE, Protocol};
use crate::proxy::session::Stream;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;

pub struct Session {
    #[allow(clippy::type_complexity)]
    reader: Arc<tokio::sync::Mutex<tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>>>,
    pub(crate) streams: Arc<Mutex<HashMap<u32, Arc<Stream>>>>,
    pub(crate) stream_id: Arc<Mutex<u32>>,
    closed: Arc<Mutex<bool>>,
    started: Arc<Mutex<bool>>,
    pub(crate) is_client: bool,
    pub(crate) protocol_state: Arc<AnyTlsState>,
    idle_notify: Arc<tokio::sync::Notify>,
    #[allow(clippy::type_complexity)]
    pub(crate) on_new_stream: Option<Arc<Box<dyn Fn(Arc<Stream>) + Send + Sync>>>,
    protocol: Arc<dyn Protocol>,
    pub(crate) frame_tx: Sender<(Frame, Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>)>,
}

impl Session {
    pub(crate) fn new_with_protocol(
        conn: Box<dyn AsyncReadWrite>,
        is_client: bool,
        on_new_stream: Option<Box<dyn Fn(Arc<Stream>) + Send + Sync>>,
        protocol: Arc<dyn Protocol>,
        protocol_state: Arc<AnyTlsState>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(conn);
        let (tx, rx) = tokio::sync::mpsc::channel::<FrameWrite>(100);
        protocol.spawn_writer_task(writer, rx, protocol_state.clone());

        Self {
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            streams: Arc::new(Mutex::new(HashMap::new())),
            stream_id: Arc::new(Mutex::new(0)),
            closed: Arc::new(Mutex::new(false)),
            started: Arc::new(Mutex::new(false)),
            is_client,
            protocol_state,
            idle_notify: Arc::new(tokio::sync::Notify::new()),
            on_new_stream: on_new_stream.map(Arc::new),
            protocol,
            frame_tx: tx,
        }
    }

    pub async fn ensure_started(&self) -> std::io::Result<()> {
        let mut started = self.started.lock().await;
        if *started {
            return Ok(());
        }

        self.protocol.on_session_start(self).await?;
        *started = true;
        Ok(())
    }

    pub async fn run(&self) -> std::io::Result<()> {
        self.ensure_started().await?;

        let result = self.recv_loop().await;
        let _ = self.close().await; // Ensure session is marked closed on exit
        result
    }

    pub(crate) async fn cancel_synack_timeout(&self, sid: u32) {
        if let Some(handle) = self.protocol_state.synack_timeout.lock().await.remove(&sid) {
            handle.abort();
        }
    }

    pub(crate) fn new_stream(&self, sid: u32) -> Stream {
        let protocol_hooks = Some(
            self.protocol
                .make_stream_protocol_hooks(self.frame_tx.clone(), self.protocol_state.clone()),
        );
        Stream::new(
            sid,
            self.frame_tx.clone(),
            Arc::downgrade(&self.streams),
            Arc::downgrade(&self.idle_notify),
            protocol_hooks,
        )
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
                let frame_len = HEADER_OVERHEAD_SIZE + frame.data.len();
                temp_buf.drain(0..frame_len);

                log::trace!(
                    "Session received frame: cmd={}, sid={}, len={}",
                    frame.cmd,
                    frame.sid,
                    frame.data.len()
                );
                self.protocol.handle_frame(self, frame).await?;
            }
        }
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
        self.protocol.open_stream(self).await
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
            let mut timeouts = self.protocol_state.synack_timeout.lock().await;
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
        *self.protocol_state.peer_version.lock().await
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
            started: self.started.clone(),
            is_client: self.is_client,
            protocol_state: self.protocol_state.clone(),
            idle_notify: self.idle_notify.clone(),
            on_new_stream: self.on_new_stream.clone(),
            protocol: self.protocol.clone(),
            frame_tx: self.frame_tx.clone(),
        }
    }
}
