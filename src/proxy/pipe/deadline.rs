use std::sync::Arc;
use tokio::sync::Notify;

pub struct PipeDeadline {
    notify: Arc<Notify>,
    timer: Option<tokio::task::JoinHandle<()>>,
}

impl PipeDeadline {
    pub fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            timer: None,
        }
    }

    pub fn set(&mut self, deadline: std::time::SystemTime) {
        if let Some(timer) = self.timer.take() {
            timer.abort();
        }

        // Compute the remaining duration from now to the deadline. If the deadline
        // is in the past or the computation fails, notify immediately.
        match deadline.duration_since(std::time::SystemTime::now()) {
            Ok(duration) => {
                let notify = self.notify.clone();
                let when = tokio::time::Instant::now() + duration;
                self.timer = Some(tokio::spawn(async move {
                    tokio::time::sleep_until(when).await;
                    notify.notify_waiters();
                }));
            }
            Err(_) => {
                // Deadline already passed: wake all waiters immediately.
                self.notify.notify_waiters();
            }
        }
    }

    pub fn wait(&self) -> &Notify {
        &self.notify
    }

    /// Return an owned cloned `Notify` so callers don't borrow `self` when waiting.
    pub fn wait_owned(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

impl Default for PipeDeadline {
    fn default() -> Self {
        Self::new()
    }
}
