use crate::proxy::pipe::PipeDeadline;
use std::io;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

pub struct PipeReader {
    pub inner: Arc<Mutex<PipeInner>>,
}

pub struct PipeWriter {
    pub inner: Arc<Mutex<PipeInner>>,
}

pub struct PipeInner {
    read_deadline: PipeDeadline,
    write_deadline: PipeDeadline,
    closed: bool,
    read_error: Option<io::Error>,
    write_error: Option<io::Error>,
    data_channel: mpsc::UnboundedSender<Vec<u8>>,
    data_receiver: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    buffer: Vec<u8>,
}

impl PipeReader {
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut receiver = {
            let mut inner = self.inner.lock().await;

            if inner.closed {
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Pipe closed"));
            }

            // Check buffer first
            if !inner.buffer.is_empty() {
                let len = inner.buffer.len().min(buf.len());
                buf[..len].copy_from_slice(&inner.buffer[..len]);
                inner.buffer.drain(0..len);
                return Ok(len);
            }

            inner.data_receiver.take().unwrap()
        };

        // We must NOT hold the lock while awaiting receiver.recv()
        let result = receiver.recv().await;

        {
            let mut inner = self.inner.lock().await;
            inner.data_receiver = Some(receiver);

            let data = result.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "No more data"))?;

            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);

            if len < data.len() {
                inner.buffer.extend_from_slice(&data[len..]);
            }

            Ok(len)
        }
    }

    pub fn close_with_error(&self, error: Option<io::Error>) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut inner = inner.lock().await;
            inner.read_error = error;
            inner.closed = true;
        });
    }

    pub async fn set_read_deadline(&self, deadline: std::time::SystemTime) -> io::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.read_deadline.set(deadline);
        Ok(())
    }
}

impl PipeWriter {
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let inner = self.inner.lock().await;

        if inner.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Pipe closed"));
        }

        if let Err(e) = inner.data_channel.send(buf.to_vec()) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, format!("Channel closed: {}", e)));
        }

        Ok(buf.len())
    }

    pub fn close_with_error(&self, error: Option<io::Error>) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut inner = inner.lock().await;
            inner.write_error = error;
            inner.closed = true;
        });
    }

    pub async fn set_write_deadline(&self, deadline: std::time::SystemTime) -> io::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.write_deadline.set(deadline);
        Ok(())
    }
}

pub fn pipe() -> (PipeReader, PipeWriter) {
    let (tx, rx) = mpsc::unbounded_channel();

    let inner = Arc::new(Mutex::new(PipeInner {
        read_deadline: PipeDeadline::new(),
        write_deadline: PipeDeadline::new(),
        closed: false,
        read_error: None,
        write_error: None,
        data_channel: tx,
        data_receiver: Some(rx),
        buffer: Vec::new(),
    }));

    (PipeReader { inner: inner.clone() }, PipeWriter { inner })
}
