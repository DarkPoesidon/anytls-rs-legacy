use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::sleep;

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

        if let Ok(duration) = deadline.duration_since(std::time::SystemTime::UNIX_EPOCH) {
            let notify = self.notify.clone();
            self.timer = Some(tokio::spawn(async move {
                sleep(duration).await;
                notify.notify_one();
            }));
        }
    }

    pub fn wait(&self) -> &Notify {
        &self.notify
    }
}

impl Default for PipeDeadline {
    fn default() -> Self {
        Self::new()
    }
}
