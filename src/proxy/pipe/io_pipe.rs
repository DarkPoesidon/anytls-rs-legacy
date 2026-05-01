use crate::proxy::pipe::PipeDeadline;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, mpsc};

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
    data_sender: Option<mpsc::UnboundedSender<Vec<u8>>>,
    data_receiver: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    buffer: Vec<u8>,
    // Notify to wake readers when receiver becomes available or pipe state changes
    read_waiter: Arc<Notify>,
}

impl PipeReader {
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // 1) Fast path: if buffer has data, consume it immediately
            {
                let mut inner = self.inner.lock().await;
                if !inner.buffer.is_empty() {
                    let len = inner.buffer.len().min(buf.len());
                    buf[..len].copy_from_slice(&inner.buffer[..len]);
                    inner.buffer.drain(0..len);
                    return Ok(len);
                }

                // If the pipe is closed and no data, return EOF or error
                if inner.closed && inner.data_sender.is_none() {
                    if let Some(err) = inner.read_error.take() {
                        return Err(err);
                    } else {
                        return Ok(0);
                    }
                }

                // If data_receiver is not available, wait until it's available or deadline triggers
                if inner.data_receiver.is_none() {
                    let waiter = inner.read_waiter.clone();
                    let deadline = inner.read_deadline.wait_owned();
                    drop(inner);

                    tokio::select! {
                        _ = waiter.notified() => continue, // try again
                        _ = deadline.notified() => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "read deadline reached")),
                    }
                }
            }

            // 2) Acquire receiver and await data or deadline
            // Take receiver under lock
            let mut receiver = self
                .inner
                .lock()
                .await
                .data_receiver
                .take()
                .ok_or(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Pipe reader already in use"))?;

            let deadline_notify = self.inner.lock().await.read_deadline.wait_owned();

            // key part: wait for data or deadline
            let res = tokio::select! {
                res = receiver.recv() => res,
                _ = deadline_notify.notified() => None,
            };

            // Restore receiver
            let mut inner = self.inner.lock().await;
            inner.data_receiver = Some(receiver);

            match res {
                Some(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    if len < data.len() {
                        inner.buffer.extend_from_slice(&data[len..]);
                    }
                    return Ok(len);
                }
                None => {
                    // Either sender dropped (EOF) or deadline
                    if let Some(err) = inner.read_error.take() {
                        return Err(err);
                    }

                    if inner.data_sender.is_none() {
                        return Ok(0);
                    } else {
                        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "read deadline reached"));
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
            inner.data_sender = None;
            // Wake any readers waiting on `read_waiter` so they observe closure/error.
            inner.read_waiter.notify_one();
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

        if let Some(tx) = &inner.data_sender {
            if let Err(e) = tx.send(buf.to_vec()) {
                return Err(Error::new(BrokenPipe, format!("Channel closed: {}", e)));
            }
            // Notify any waiting readers that data is available
            inner.read_waiter.notify_one();
            Ok(buf.len())
        } else {
            Err(Error::new(BrokenPipe, "Pipe closed"))
        }
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
        data_sender: Some(tx),
        data_receiver: Some(rx),
        buffer: Vec::new(),
        read_waiter: Arc::new(Notify::new()),
    }));

    (PipeReader { inner: inner.clone() }, PipeWriter { inner })
}
