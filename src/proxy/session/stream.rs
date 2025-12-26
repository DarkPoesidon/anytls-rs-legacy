use crate::proxy::pipe::{PipeReader, PipeWriter, pipe};
use crate::proxy::session::frame::{CMD_PSH, Frame};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::Sender;

pub struct Stream {
    id: u32,
    pipe_reader: PipeReader,
    pipe_writer: PipeWriter,
    frame_tx: Sender<Frame>,
    closed: Arc<tokio::sync::Mutex<bool>>,
    reported: Arc<tokio::sync::Mutex<bool>>,
}

impl Stream {
    pub fn new(id: u32, frame_tx: Sender<Frame>) -> Self {
        let (pipe_reader, pipe_writer) = pipe();

        Self {
            id,
            pipe_reader,
            pipe_writer,
            frame_tx,
            closed: Arc::new(tokio::sync::Mutex::new(false)),
            reported: Arc::new(tokio::sync::Mutex::new(false)),
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
        match self.frame_tx.send(frame).await {
            Ok(_) => Ok(buf.len()),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Session closed")),
        }
    }

    pub async fn push_data(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.pipe_writer.write(buf).await
    }

    pub async fn close(&self) -> std::io::Result<()> {
        log::debug!("Stream {} close", self.id);
        use std::io::{Error, ErrorKind::BrokenPipe};
        self.close_with_error(Some(Error::new(BrokenPipe, "Stream closed"))).await
    }

    pub async fn close_with_error(&self, error: Option<std::io::Error>) -> std::io::Result<()> {
        {
            let mut closed = self.closed.lock().await;
            if *closed {
                return Ok(());
            }
            *closed = true;
        }

        self.pipe_reader.close_with_error(error);

        // Send FIN asynchronously to avoid blocking the session loop
        let frame = Frame::new(crate::proxy::session::frame::CMD_FIN, self.id);
        let tx = self.frame_tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(frame).await;
        });

        Ok(())
    }

    pub async fn handshake_failure(&self, _err: &str) -> std::io::Result<()> {
        {
            let mut reported = self.reported.lock().await;
            if *reported {
                return Ok(());
            }
            *reported = true;
        }

        // Simplified implementation
        Ok(())
    }

    pub async fn handshake_success(&self) -> std::io::Result<()> {
        {
            let mut reported = self.reported.lock().await;
            if *reported {
                return Ok(());
            }
            *reported = true;
        }

        // Simplified implementation
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
            closed: self.closed.clone(),
            reported: self.reported.clone(),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Allocate a temporary buffer to receive data from the PipeReader.
        // We copy the received bytes into the provided ReadBuf on success.
        let remaining = buf.remaining();
        if remaining == 0 {
            return std::task::Poll::Ready(Ok(()));
        }

        // Create a future that owns its buffer so we don't hold a mutable borrow across await points.
        let inner = self.pipe_reader.inner.clone();
        let mut fut = Box::pin(async move {
            let reader = PipeReader { inner };
            let mut v = vec![0u8; remaining];
            let n = reader.read(&mut v).await?;
            Ok::<(Vec<u8>, usize), std::io::Error>((v, n))
        });

        match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok((v, n))) => {
                buf.put_slice(&v[..n]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
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
