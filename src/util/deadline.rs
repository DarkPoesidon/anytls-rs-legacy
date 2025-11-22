use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::sleep;

pub struct DeadlineWatcher {
    notify: Arc<Notify>,
    #[allow(unused)]
    timeout: Duration,
}

impl DeadlineWatcher {
    pub fn new(timeout: Duration, callback: impl FnOnce() + Send + 'static) -> Self {
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();

        tokio::spawn(async move {
            sleep(timeout).await;
            callback();
            notify_clone.notify_one();
        });

        Self { notify, timeout }
    }

    pub async fn wait(&self) {
        self.notify.notified().await;
    }
}
