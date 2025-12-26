use crate::proxy::pipe::PipeDeadline;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

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
    read_error: Option<std::io::Error>,
    write_error: Option<std::io::Error>,
    data_channel: Option<mpsc::UnboundedSender<Vec<u8>>>,
    data_receiver: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    buffer: Vec<u8>,
}

impl PipeReader {
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut receiver = {
            let mut inner = self.inner.lock().await;

            // Check buffer first
            if !inner.buffer.is_empty() {
                let len = inner.buffer.len().min(buf.len());
                buf[..len].copy_from_slice(&inner.buffer[..len]);
                inner.buffer.drain(0..len);
                return Ok(len);
            }

            // Note: We do NOT check inner.closed here.
            // We rely on receiver.recv() returning None to indicate end of stream.
            // This ensures we drain any pending data in the channel even if closed=true.

            inner
                .data_receiver
                .take()
                .ok_or(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Pipe reader already in use"))?
        };

        // We must NOT hold the lock while awaiting receiver.recv()
        let result = receiver.recv().await;

        {
            let mut inner = self.inner.lock().await;
            inner.data_receiver = Some(receiver);

            match result {
                Some(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);

                    if len < data.len() {
                        inner.buffer.extend_from_slice(&data[len..]);
                    }
                    Ok(len)
                }
                None => {
                    // Channel closed (Sender dropped)
                    if let Some(err) = &inner.read_error {
                        Err(std::io::Error::new(err.kind(), err.to_string()))
                    } else {
                        Ok(0) // EOF
                    }
                }
            }
        }
    }

    pub fn close_with_error(&self, error: Option<std::io::Error>) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut inner = inner.lock().await;
            inner.read_error = error;
            inner.closed = true;
            inner.data_channel = None;
        });
    }

    pub async fn set_read_deadline(&self, deadline: std::time::SystemTime) -> std::io::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.read_deadline.set(deadline);
        Ok(())
    }
}

impl PipeWriter {
    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        use std::io::{Error, ErrorKind::BrokenPipe};
        let inner = self.inner.lock().await;

        if inner.closed {
            return Err(Error::new(BrokenPipe, "Pipe closed"));
        }

        if let Some(tx) = &inner.data_channel {
            if let Err(e) = tx.send(buf.to_vec()) {
                return Err(Error::new(BrokenPipe, format!("Channel closed: {}", e)));
            }
        } else {
            return Err(Error::new(BrokenPipe, "Pipe closed"));
        }

        Ok(buf.len())
    }

    pub fn close_with_error(&self, error: Option<std::io::Error>) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut inner = inner.lock().await;
            inner.write_error = error;
            inner.closed = true;
            inner.data_channel = None;
        });
    }

    pub async fn set_write_deadline(&self, deadline: std::time::SystemTime) -> std::io::Result<()> {
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
        data_channel: Some(tx),
        data_receiver: Some(rx),
        buffer: Vec::new(),
    }));

    (PipeReader { inner: inner.clone() }, PipeWriter { inner })
}
