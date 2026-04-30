use crate::AsyncReadWrite;
use crate::core::{Command, Frame, HEADER_OVERHEAD_SIZE, State};
use crate::proxy::pipe::{PipeReader, PipeWriter, pipe};
use crate::runtime::{FrameWrite, Protocol, ProtocolHost, WriterRuntimeState};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;

pub struct Session {
    #[allow(clippy::type_complexity)]
    reader: Arc<tokio::sync::Mutex<tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>>>,
    // pipe for the single logical stream
    pipe_reader: PipeReader,
    pipe_writer: PipeWriter,
    // protocol hooks for session-level handshake notifications
    protocol_hooks: Option<Arc<dyn crate::runtime::SessionProtocolHooks>>,
    // whether the logical stream is open
    stream_open: Arc<Mutex<bool>>,
    // single synack timeout handle (for the only stream)
    synack_timeout: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    closed: Arc<Mutex<bool>>,
    started: Arc<Mutex<bool>>,
    pub(crate) is_client: bool,
    pub(crate) protocol_state: Arc<State>,
    writer_state: Arc<WriterRuntimeState>,
    idle_notify: Arc<tokio::sync::Notify>,
    #[allow(clippy::type_complexity)]
    pub(crate) on_new_session: Option<Arc<Box<dyn Fn(Arc<Session>) + Send + Sync>>>,
    protocol: Arc<dyn Protocol>,
    pub(crate) frame_tx: Sender<(Frame, Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>)>,
}

impl Session {
    pub(crate) fn new_with_protocol(
        conn: Box<dyn AsyncReadWrite>,
        is_client: bool,
        on_new_session: Option<Box<dyn Fn(Arc<Session>) + Send + Sync>>,
        protocol: Arc<dyn Protocol>,
        protocol_state: Arc<State>,
        writer_state: Arc<WriterRuntimeState>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(conn);
        let (tx, rx) = tokio::sync::mpsc::channel::<FrameWrite>(100);
        let (pr, pw) = pipe();
        let session = Self {
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            pipe_reader: pr,
            pipe_writer: pw,
            protocol_hooks: None,
            stream_open: Arc::new(Mutex::new(false)),
            synack_timeout: Arc::new(Mutex::new(None)),
            closed: Arc::new(Mutex::new(false)),
            started: Arc::new(Mutex::new(false)),
            is_client,
            protocol_state,
            writer_state,
            idle_notify: Arc::new(tokio::sync::Notify::new()),
            on_new_session: on_new_session.map(Arc::new),
            protocol,
            frame_tx: tx,
        };

        // create session-level protocol hooks from protocol implementation
        let hooks = session
            .protocol
            .make_session_protocol_hooks(session.frame_tx.clone(), session.protocol_state.clone());
        // set hooks
        let mut s = session.clone();
        s.protocol_hooks = Some(hooks);

        s.protocol
            .spawn_writer_task(writer, rx, s.protocol_state.clone(), s.writer_state.clone());

        s
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
        if sid == crate::proxy::session::DEFAULT_SID
            && let Some(handle) = self.synack_timeout.lock().await.take()
        {
            handle.abort();
        }
    }

    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.pipe_reader.read(buf).await
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        log::trace!("Session write {} bytes", buf.len());
        let frame = Frame::with_data(Command::Psh, crate::proxy::session::DEFAULT_SID, bytes::Bytes::copy_from_slice(buf));
        match self.frame_tx.send((frame, None)).await {
            Ok(_) => Ok(buf.len()),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
        }
    }

    pub async fn push_data(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.pipe_writer.write(buf).await
    }

    pub async fn handshake_failure(&self, error: &str) -> std::io::Result<()> {
        if let Some(hooks) = &self.protocol_hooks {
            hooks.handshake_failure(error).await?;
        }
        Ok(())
    }

    pub async fn handshake_success(&self) -> std::io::Result<()> {
        if let Some(hooks) = &self.protocol_hooks {
            hooks.handshake_success().await?;
        }
        Ok(())
    }

    // no new_stream: session itself acts as the single logical stream

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

                // Allow session-control frames (sid == 0) and the single logical
                // data stream `DEFAULT_SID`. Reject other sids (multiplexed
                // streams) which we no longer support.
                if frame.sid != 0 && frame.sid != crate::proxy::session::DEFAULT_SID {
                    log::warn!(
                        "Received frame for unsupported sid {} (only 0 and {} supported). Sending Alert and closing session",
                        frame.sid,
                        crate::proxy::session::DEFAULT_SID
                    );

                    let message = format!("unsupported sid {}", frame.sid);
                    let alert = Frame::with_data(Command::Alert, 0, Bytes::copy_from_slice(message.as_bytes()));
                    // best-effort notify peer synchronously, then abort
                    let _ = self.write_frame_sync(alert).await;

                    return Err(std::io::Error::other(format!("unsupported sid {}", frame.sid)));
                }

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

    pub async fn open_stream(&self) -> std::io::Result<Arc<Session>> {
        // single-stream session: always return the session itself
        // but ensure protocol open_stream is called
        let id = crate::proxy::session::DEFAULT_SID;
        if let Err(err) = self.protocol.open_stream(self, id).await {
            self.cancel_synack_timeout(id).await;
            return Err(err);
        }
        // mark logical stream open
        *self.stream_open.lock().await = true;
        Ok(Arc::new(self.clone()))
    }

    pub async fn close(&self) -> std::io::Result<()> {
        {
            let mut closed = self.closed.lock().await;
            if *closed {
                return Ok(());
            }
            *closed = true;
        }

        if let Some(handle) = self.synack_timeout.lock().await.take() {
            handle.abort();
        }

        // close logical stream pipe
        self.pipe_reader.close_with_error(None);

        Ok(())
    }

    pub async fn is_closed(&self) -> bool {
        *self.closed.lock().await || self.frame_tx.is_closed()
    }

    pub async fn peer_version(&self) -> u8 {
        self.protocol_state.peer_version()
    }

    pub async fn wait_for_idle(&self) {
        self.idle_notify.notified().await;
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            pipe_reader: PipeReader {
                inner: self.pipe_reader.inner.clone(),
            },
            pipe_writer: PipeWriter {
                inner: self.pipe_writer.inner.clone(),
            },
            protocol_hooks: self.protocol_hooks.clone(),
            stream_open: self.stream_open.clone(),
            synack_timeout: self.synack_timeout.clone(),
            closed: self.closed.clone(),
            started: self.started.clone(),
            is_client: self.is_client,
            protocol_state: self.protocol_state.clone(),
            writer_state: self.writer_state.clone(),
            idle_notify: self.idle_notify.clone(),
            on_new_session: self.on_new_session.clone(),
            protocol: self.protocol.clone(),
            frame_tx: self.frame_tx.clone(),
        }
    }
}

#[async_trait]
impl ProtocolHost for Session {
    fn is_client(&self) -> bool {
        self.is_client
    }

    fn protocol_state(&self) -> Arc<State> {
        self.protocol_state.clone()
    }

    async fn send_frame(&self, frame: Frame) -> std::io::Result<usize> {
        Session::write_frame(self, frame).await
    }

    async fn send_frame_sync(&self, frame: Frame) -> std::io::Result<usize> {
        Session::write_frame_sync(self, frame).await
    }

    async fn push_stream_data(&self, sid: u32, data: Bytes) -> std::io::Result<()> {
        if sid == crate::proxy::session::DEFAULT_SID {
            self.push_data(data.as_ref()).await?;
        }
        Ok(())
    }

    async fn ensure_incoming_stream(&self, sid: u32) -> std::io::Result<()> {
        if sid != crate::proxy::session::DEFAULT_SID {
            // only single stream supported; ignore other ids
            return Ok(());
        }
        let mut open = self.stream_open.lock().await;
        if !*open {
            log::debug!("Session received SYN for stream {sid}");
            *open = true;

            if let Some(callback) = &self.on_new_session {
                callback(Arc::new(self.clone()));
            }
        }
        Ok(())
    }

    async fn close_local_stream(&self, sid: u32) -> std::io::Result<()> {
        log::debug!("Session received FIN for stream {}", sid);
        if sid == crate::proxy::session::DEFAULT_SID {
            self.pipe_reader.close_with_error(None);
            *self.stream_open.lock().await = false;
            self.idle_notify.notify_waiters();
        }
        Ok(())
    }

    async fn close_remote_stream(&self, sid: u32, message: String) -> std::io::Result<()> {
        if sid == crate::proxy::session::DEFAULT_SID {
            self.pipe_reader
                .close_with_error(Some(std::io::Error::other(format!("remote: {message}"))));
            *self.stream_open.lock().await = false;
        }
        Ok(())
    }

    async fn cancel_synack_timeout(&self, sid: u32) {
        if sid == crate::proxy::session::DEFAULT_SID
            && let Some(handle) = self.synack_timeout.lock().await.take()
        {
            handle.abort();
        }
    }

    async fn arm_synack_timeout(&self, sid: u32, timeout: std::time::Duration) {
        if sid != crate::proxy::session::DEFAULT_SID {
            return;
        }

        let session_clone = self.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let _ = session_clone.close().await;
        });
        let mut guard = self.synack_timeout.lock().await;
        *guard = Some(handle);
    }

    async fn release_write_buffering(&self) {
        self.writer_state.set_buffering(false).await;
    }
}
