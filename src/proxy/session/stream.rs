use crate::proxy::pipe::{pipe, PipeReader, PipeWriter};
use crate::proxy::session::frame::{Frame, CMD_PSH};
use std::io;
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

    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.pipe_reader.read(buf).await?;
        if n > 0 {
            log::debug!("Stream {} read {} bytes", self.id, n);
        }
        Ok(n)
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        log::debug!("Stream {} write {} bytes", self.id, buf.len());
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

        // Send FIN
        let frame = Frame::new(crate::proxy::session::frame::CMD_FIN, self.id);
        let _ = self.frame_tx.send(frame).await;

        Ok(())
    }

    pub async fn handshake_failure(&self, _err: &str) -> io::Result<()> {
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

    pub async fn handshake_success(&self) -> io::Result<()> {
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

    pub async fn set_read_deadline(&self, deadline: std::time::SystemTime) -> io::Result<()> {
        self.pipe_reader.set_read_deadline(deadline).await
    }

    pub async fn set_write_deadline(&self, deadline: std::time::SystemTime) -> io::Result<()> {
        self.pipe_writer.set_write_deadline(deadline).await
    }

    pub async fn set_deadline(&self, deadline: std::time::SystemTime) -> io::Result<()> {
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
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // Simplified implementation - in a real implementation, this would be more complex
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        // Simplified implementation - in a real implementation, this would be more complex
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
