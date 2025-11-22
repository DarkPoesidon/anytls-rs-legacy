use std::time::Duration;
use tokio::time::interval;

pub fn start_routine<F>(mut f: F, duration: Duration)
where
    F: FnMut() + Send + 'static,
{
    tokio::spawn(async move {
        let mut interval = interval(duration);
        loop {
            interval.tick().await;
            f();
        }
    });
}
