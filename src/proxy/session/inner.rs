use crate::AsyncReadWrite;
use crate::core::{Command, Frame, HEADER_OVERHEAD_SIZE, State};
use crate::proxy::pipe::{PipeReader, PipeWriter, pipe};
use crate::proxy::session::DEFAULT_SID;
use crate::runtime::{FrameWrite, Protocol, ProtocolHost, WriterRuntimeState};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;

#[derive(Clone, Copy, Debug, Default)]
struct StreamState {
    local_open: bool,
    remote_open: bool,
}

impl StreamState {
    fn open_both(&mut self) {
        self.local_open = true;
        self.remote_open = true;
    }

    fn is_active(&self) -> bool {
        self.local_open || self.remote_open
    }
}

static SESSION_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub struct Session {
    pub id: u64,
    #[allow(clippy::type_complexity)]
    reader: Arc<tokio::sync::Mutex<tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>>>,
    // pipe for the single logical stream
    pipe_reader: PipeReader,
    pipe_writer: PipeWriter,
    // protocol hooks for session-level handshake notifications
    protocol_hooks: Option<Arc<dyn crate::runtime::SessionProtocolHooks>>,
    // track local and remote half-close state for the single logical stream
    stream_state: Arc<Mutex<StreamState>>,
    // single synack timeout handle (for the only stream)
    closed: Arc<Mutex<bool>>,
    started: Arc<Mutex<bool>>,
    handler_started: Arc<Mutex<bool>>,
    pub(crate) is_client: bool,
    pub(crate) protocol_state: Arc<State>,
    writer_state: Arc<WriterRuntimeState>,
    idle_notify: Arc<tokio::sync::Notify>,
    handshake_notify: Arc<tokio::sync::Notify>,
    handshake_result: Arc<Mutex<Option<Result<(), String>>>>,
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
            id: SESSION_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            pipe_reader: pr,
            pipe_writer: pw,
            protocol_hooks: None,
            stream_state: Arc::new(Mutex::new(StreamState::default())),
            closed: Arc::new(Mutex::new(false)),
            started: Arc::new(Mutex::new(false)),
            handler_started: Arc::new(Mutex::new(false)),
            is_client,
            protocol_state,
            writer_state,
            idle_notify: Arc::new(tokio::sync::Notify::new()),
            handshake_notify: Arc::new(tokio::sync::Notify::new()),
            handshake_result: Arc::new(Mutex::new(None)),
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
        log::debug!("Session::ensure_started: is_client={}", self.is_client);
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
        let _ = self.terminate().await; // Ensure session is marked closed on exit
        result
    }

    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.pipe_reader.read(buf).await
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        log::trace!("Session write {} bytes", buf.len());
        log::debug!("Session queueing Psh frame len={}", buf.len());
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
        log::debug!("Session::recv_loop: begin loop (is_client={})", self.is_client);

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
                let frame_sid = frame.sid;
                let frame_len = HEADER_OVERHEAD_SIZE + frame.data.len();
                temp_buf.drain(0..frame_len);

                let frame_type = if frame_sid == 0 {
                    "control"
                } else if frame_sid == DEFAULT_SID {
                    "data"
                } else {
                    "unsupported"
                };

                log::trace!("Session received frame: {} ({})", frame, frame_type);

                // Allow session-control frames (sid == 0) and the single logical
                // data stream `DEFAULT_SID`. Reject other sids (multiplexed
                // streams) which we no longer support.
                if frame_sid != 0 && frame_sid != DEFAULT_SID {
                    log::warn!(
                        "Received frame for unsupported sid {} (only 0 and {} supported). Sending Alert and closing session",
                        frame_sid,
                        DEFAULT_SID
                    );

                    let message = format!("unsupported sid {}", frame_sid);
                    let alert = Frame::with_data(Command::Alert, 0, Bytes::copy_from_slice(message.as_bytes()));
                    // best-effort notify peer synchronously, then abort
                    let _ = self.write_frame_sync(alert).await;

                    return Err(std::io::Error::other(format!("unsupported sid {}", frame_sid)));
                }

                // If we receive data for the single logical stream before an
                // explicit SYN/EnsureIncomingStream, treat the first PSH as an
                // implicit open: ensure the incoming stream callback is run so
                // the application handler can start reading from the session.
                if frame.cmd == Command::Psh {
                    if frame_sid == DEFAULT_SID {
                        let open = self.stream_state.lock().await.is_active();
                        if !open {
                            let _ = self.ensure_incoming_stream(frame_sid).await;
                        }
                    } else {
                        log::warn!("Received data frame for unsupported sid {frame_sid} (only {DEFAULT_SID} supported), ignoring");
                    }
                }

                if self.is_client && frame.cmd == Command::SynAck && frame_sid == DEFAULT_SID {
                    let result = if frame.data.is_empty() {
                        Ok(())
                    } else {
                        Err(String::from_utf8_lossy(frame.data.as_ref()).to_string())
                    };
                    *self.handshake_result.lock().await = Some(result);
                    self.handshake_notify.notify_waiters();
                }

                self.protocol.handle_frame(self, frame).await?;
            }

            const LARGE_RECV_BUFFER_WARN_THRESHOLD: usize = 16 * 1024 + HEADER_OVERHEAD_SIZE;
            if temp_buf.len() > LARGE_RECV_BUFFER_WARN_THRESHOLD {
                log::warn!("Session::recv_loop temp_buf growing large after parse: {} bytes", temp_buf.len());
            }
        }
    }

    async fn _read_exact(&self, n: usize) -> std::io::Result<Vec<u8>> {
        let buffer = vec![0u8; n];
        Ok(buffer)
    }

    pub async fn write_frame(&self, frame: Frame) -> std::io::Result<usize> {
        let len = frame.data.len();
        log::debug!("Session sending frame: {frame}");
        match self.frame_tx.send((frame, None)).await {
            Ok(_) => Ok(len),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
        }
    }

    pub async fn write_frame_sync(&self, frame: Frame) -> std::io::Result<usize> {
        let len = frame.data.len();
        log::debug!("Session sending frame sync: {frame}");
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
        // single-stream session: always return the session itself.
        // Opening a logical stream resets both local and remote half-close
        // state so the session stays active until both directions finish.
        let mut state = self.stream_state.lock().await;
        if state.is_active() {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "Session stream already active"));
        }

        state.open_both();
        *self.handshake_result.lock().await = None;
        Ok(Arc::new(self.clone()))
    }

    pub async fn wait_for_stream_handshake(&self) -> std::io::Result<()> {
        loop {
            if let Some(result) = self.handshake_result.lock().await.clone() {
                return result.map_err(std::io::Error::other);
            }

            if self.is_terminated().await {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Session terminated before handshake completed",
                ));
            }

            self.handshake_notify.notified().await;
        }
    }

    pub async fn mark_local_stream_closed(&self, sid: u32) -> std::io::Result<()> {
        if sid != DEFAULT_SID {
            log::warn!("Received mark_local_stream_closed for unsupported sid {sid} (only {DEFAULT_SID} supported), ignoring",);
            return Ok(());
        }

        let should_notify_idle = {
            let mut state = self.stream_state.lock().await;
            if !state.local_open {
                false
            } else {
                state.local_open = false;
                !state.remote_open
            }
        };

        if should_notify_idle {
            log::trace!("Session local half closed; notifying idle waiters for sid {}", sid);
            self.idle_notify.notify_waiters();
        }

        Ok(())
    }

    /// Terminate the entire session and underlying resources. This represents
    /// a hard termination (session end), not merely a logical stream close.
    pub async fn terminate(&self) -> std::io::Result<()> {
        {
            let mut closed = self.closed.lock().await;
            if *closed {
                return Ok(());
            }
            *closed = true;
        }

        // close logical stream pipe without an error (EOF)
        self.pipe_reader.close_with_error(None);

        // Wake any idle waiters so they can observe the terminated state and exit.
        self.idle_notify.notify_waiters();
        self.handshake_notify.notify_waiters();

        Ok(())
    }

    pub async fn is_terminated(&self) -> bool {
        *self.closed.lock().await || self.frame_tx.is_closed()
    }

    pub async fn peer_version(&self) -> u8 {
        self.protocol_state.peer_version()
    }

    pub async fn wait_for_idle(&self) {
        self.idle_notify.notified().await;
    }

    pub async fn is_stream_open(&self) -> bool {
        self.stream_state.lock().await.is_active()
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            reader: self.reader.clone(),
            pipe_reader: PipeReader {
                inner: self.pipe_reader.inner.clone(),
            },
            pipe_writer: PipeWriter {
                inner: self.pipe_writer.inner.clone(),
            },
            protocol_hooks: self.protocol_hooks.clone(),
            stream_state: self.stream_state.clone(),
            closed: self.closed.clone(),
            started: self.started.clone(),
            handler_started: self.handler_started.clone(),
            is_client: self.is_client,
            protocol_state: self.protocol_state.clone(),
            writer_state: self.writer_state.clone(),
            idle_notify: self.idle_notify.clone(),
            handshake_notify: self.handshake_notify.clone(),
            handshake_result: self.handshake_result.clone(),
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
        log::debug!("Session push_stream_data sid={} len={}", sid, data.len());
        if sid == DEFAULT_SID {
            self.push_data(data.as_ref()).await?;
        } else {
            log::warn!("Received push_stream_data for unsupported sid {sid} (only {DEFAULT_SID} supported)",);
        }
        Ok(())
    }

    async fn ensure_incoming_stream(&self, sid: u32) -> std::io::Result<()> {
        if sid != DEFAULT_SID {
            // only single stream supported; ignore other ids
            log::warn!("Received ensure_incoming_stream for unsupported sid {sid} (only {DEFAULT_SID} supported), ignoring",);
            return Ok(());
        }
        let should_start_handler = {
            let mut state = self.stream_state.lock().await;
            if state.is_active() {
                false
            } else {
                log::trace!("Session received SYN for stream {sid}");
                state.open_both();

                let mut handler_started = self.handler_started.lock().await;
                if *handler_started {
                    false
                } else {
                    *handler_started = true;
                    true
                }
            }
        };

        if should_start_handler && let Some(callback) = &self.on_new_session {
            callback(Arc::new(self.clone()));
        }
        Ok(())
    }

    async fn close_logical_stream(&self, sid: u32) -> std::io::Result<()> {
        log::trace!("Session received FIN for stream {}", sid);
        if sid == DEFAULT_SID {
            let (was_open, should_notify_idle) = {
                let mut state = self.stream_state.lock().await;
                if !state.remote_open {
                    (false, false)
                } else {
                    state.remote_open = false;
                    (true, !state.local_open)
                }
            };

            if !was_open {
                log::trace!("Session stream {} already closed, ignoring duplicate FIN", sid);
                return Ok(());
            }

            // Logical stream finished; mark the stream as closed but keep
            // the underlying session active for reuse.
            self.pipe_reader.finish_stream(None).await;
            // Only push the session back to idle after both halves closed.
            if should_notify_idle {
                log::trace!("Session remote half closed; notifying idle waiters for sid {}", sid);
                self.idle_notify.notify_waiters();
            }
        } else {
            log::warn!("Received close_logical_stream for unsupported sid {sid} (only {DEFAULT_SID} supported), ignoring",);
        }
        Ok(())
    }

    async fn terminate_session(&self, sid: u32, message: Option<String>) -> std::io::Result<()> {
        if sid == DEFAULT_SID {
            if let Some(msg) = message {
                // Remote indicated an error/termination reason: surface as error
                // on the logical pipe and mark session terminated.
                self.pipe_reader
                    .close_with_error(Some(std::io::Error::other(format!("remote: {msg}"))));
            } else {
                // No message: close pipe normally.
                self.pipe_reader.close_with_error(None);
            }

            *self.stream_state.lock().await = StreamState::default();

            // Mark session as closed/terminated so recv_loop and other tasks
            // will observe terminal state and clean up. Also wake idle
            // waiters so they don't remain blocked.
            let mut closed = self.closed.lock().await;
            *closed = true;
            self.idle_notify.notify_waiters();
        } else {
            log::warn!("Received terminate_session for unsupported sid {sid} (only {DEFAULT_SID} supported), ignoring",);
        }
        Ok(())
    }

    async fn release_write_buffering(&self) {
        self.writer_state.set_buffering(false).await;
    }
}

#[cfg(test)]
mod tests {
    use super::Session;
    use crate::proxy::session::DEFAULT_SID;
    use crate::runtime::{DefaultPaddingFactory, ProtocolHost};
    use std::time::Duration;
    use tokio::io::duplex;
    use tokio::time::timeout;

    #[tokio::test]
    async fn duplicate_fin_does_not_poison_next_logical_stream() {
        let (client_io, _peer_io) = duplex(1024);
        let session = Session::new_with_protocol(
            Box::new(client_io),
            true,
            None,
            std::sync::Arc::new(crate::runtime::AnyTlsProtocol),
            crate::core::State::new(DefaultPaddingFactory::load().read().await.clone()),
            crate::runtime::WriterRuntimeState::new(true),
        );

        session.open_stream().await.expect("first logical stream should open");
        session
            .mark_local_stream_closed(DEFAULT_SID)
            .await
            .expect("local FIN should close the local half");
        session
            .close_logical_stream(DEFAULT_SID)
            .await
            .expect("first FIN should close the logical stream");

        let mut buf = [0u8; 16];
        let eof_len = timeout(Duration::from_secs(1), session.read(&mut buf))
            .await
            .expect("first EOF should arrive")
            .expect("first EOF read should succeed");
        assert_eq!(eof_len, 0, "first FIN should produce exactly one EOF");

        session
            .close_logical_stream(DEFAULT_SID)
            .await
            .expect("duplicate FIN should be ignored cleanly");
        tokio::task::yield_now().await;

        session.open_stream().await.expect("second logical stream should open");
        session
            .push_data(b"hello")
            .await
            .expect("reused logical stream should accept payload");

        let payload_len = timeout(Duration::from_secs(1), session.read(&mut buf))
            .await
            .expect("reused logical stream should produce payload")
            .expect("payload read should succeed");
        assert_eq!(payload_len, 5, "duplicate FIN must not leave a stale EOF behind");
        assert_eq!(&buf[..payload_len], b"hello");
    }
}
