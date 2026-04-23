use crate::protocol::StreamProtocolHooks;
use crate::protocol::{CMD_FIN, CMD_PSH, Frame};
use crate::proxy::pipe::{PipeReader, PipeWriter, pipe};
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tokio::io::AsyncWrite;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, Notify};

pub struct Stream {
    id: u32,
    pipe_reader: PipeReader,
    pipe_writer: PipeWriter,
    frame_tx: Sender<(Frame, Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>)>,
    streams: Weak<Mutex<HashMap<u32, Arc<Stream>>>>,
    idle_notify: Weak<Notify>,
    protocol_hooks: Option<Arc<dyn StreamProtocolHooks>>,
    closed: Arc<tokio::sync::Mutex<bool>>,
}

impl Stream {
    pub(crate) fn new(
        id: u32,
        frame_tx: Sender<(Frame, Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>)>,
        streams: Weak<Mutex<HashMap<u32, Arc<Stream>>>>,
        idle_notify: Weak<Notify>,
        protocol_hooks: Option<Arc<dyn StreamProtocolHooks>>,
    ) -> Self {
        let (pipe_reader, pipe_writer) = pipe();

        Self {
            id,
            pipe_reader,
            pipe_writer,
            frame_tx,
            streams,
            idle_notify,
            protocol_hooks,
            closed: Arc::new(tokio::sync::Mutex::new(false)),
        }
    }

    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.pipe_reader.read(buf).await?;
        if n > 0 {
            log::trace!("Stream {} read {} bytes", self.id, n);
        }
        Ok(n)
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        log::trace!("Stream {} write {} bytes", self.id, buf.len());
        let frame = Frame::with_data(CMD_PSH, self.id, bytes::Bytes::copy_from_slice(buf));
        match self.frame_tx.send((frame, None)).await {
            Ok(_) => Ok(buf.len()),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
        }
    }

    pub async fn push_data(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.pipe_writer.write(buf).await
    }

    pub async fn close(&self) -> std::io::Result<()> {
        log::debug!("Stream {} close requested", self.id);
        use std::io::{Error, ErrorKind::BrokenPipe};
        self.close_with_error(Some(Error::new(BrokenPipe, "Stream closed"))).await
    }

    async fn mark_closed(&self, error: Option<std::io::Error>) -> std::io::Result<bool> {
        {
            let mut closed = self.closed.lock().await;
            if *closed {
                return Ok(false);
            }
            *closed = true;
        }

        self.pipe_reader.close_with_error(error);

        Ok(true)
    }

    async fn remove_from_session_state(&self) {
        if let Some(streams) = self.streams.upgrade() {
            let mut streams = streams.lock().await;
            streams.remove(&self.id);
            if streams.is_empty()
                && let Some(idle_notify) = self.idle_notify.upgrade()
            {
                idle_notify.notify_waiters();
            }
        }
    }

    pub async fn close_local_with_error(&self, error: Option<std::io::Error>) -> std::io::Result<()> {
        if !self.mark_closed(error).await? {
            return Ok(());
        }

        self.remove_from_session_state().await;

        Ok(())
    }

    pub async fn close_with_error(&self, error: Option<std::io::Error>) -> std::io::Result<()> {
        if !self.mark_closed(error).await? {
            return Ok(());
        }

        self.remove_from_session_state().await;

        // Send FIN asynchronously to avoid blocking the session loop
        let frame = Frame::new(CMD_FIN, self.id);
        let tx = self.frame_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = tx.send((frame, None)).await {
                log::error!("Failed to send FIN frame: {e}");
            }
        });

        Ok(())
    }

    pub async fn handshake_failure(&self, error: &str) -> std::io::Result<()> {
        if let Some(protocol_hooks) = &self.protocol_hooks {
            protocol_hooks.handshake_failure(self.id, error).await?;
        }

        Ok(())
    }

    pub async fn handshake_success(&self) -> std::io::Result<()> {
        if let Some(protocol_hooks) = &self.protocol_hooks {
            protocol_hooks.handshake_success(self.id).await?;
        }

        Ok(())
    }

    pub async fn set_read_deadline(&self, deadline: std::time::SystemTime) -> std::io::Result<()> {
        self.pipe_reader.set_read_deadline(deadline).await
    }

    pub async fn set_write_deadline(&self, deadline: std::time::SystemTime) -> std::io::Result<()> {
        self.pipe_writer.set_write_deadline(deadline).await
    }

    pub async fn set_deadline(&self, deadline: std::time::SystemTime) -> std::io::Result<()> {
        self.set_write_deadline(deadline).await?;
        self.set_read_deadline(deadline).await
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn split(self) -> (Self, Self) {
        (self.clone(), self)
    }

    pub fn split_ref(&self) -> (Self, Self) {
        (self.clone(), self.clone())
    }
}

impl Clone for Stream {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            pipe_reader: PipeReader {
                inner: self.pipe_reader.inner.clone(),
            },
            pipe_writer: PipeWriter {
                inner: self.pipe_writer.inner.clone(),
            },
            frame_tx: self.frame_tx.clone(),
            streams: self.streams.clone(),
            idle_notify: self.idle_notify.clone(),
            protocol_hooks: self.protocol_hooks.clone(),
            closed: self.closed.clone(),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        use std::task::Poll;

        // Forward to PipeWriter::write() and poll the future.
        let mut fut = Box::pin(self.pipe_writer.write(buf));
        match fut.as_mut().poll(cx) {
            Poll::Ready(res) => Poll::Ready(res),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
        // Pipe has no flush semantics; pretend it's flushed.
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
        // Nothing special to do on shutdown.
        std::task::Poll::Ready(Ok(()))
    }
}
