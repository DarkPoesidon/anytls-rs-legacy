use crate::DialOutFunc;
use crate::core::PaddingFactory;
use crate::proxy::session::Session;
use crate::runtime::new_client_session;
use indexmap::IndexMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;

pub struct Client {
    dial_out: DialOutFunc,
    sessions: Arc<Mutex<IndexMap<u64, Arc<Session>>>>,
    #[allow(clippy::type_complexity)]
    idle_sessions: Arc<Mutex<Vec<(u64, Arc<Session>, Instant)>>>,
    session_counter: Arc<Mutex<u64>>,
    padding: Arc<RwLock<PaddingFactory>>,
    idle_session_timeout: Duration,
    min_idle_sessions: usize,
}

impl Client {
    pub fn new(
        dial_out: DialOutFunc,
        padding: Arc<RwLock<PaddingFactory>>,
        idle_session_check_interval: Duration,
        idle_session_timeout: Duration,
        min_idle_sessions: usize,
    ) -> Self {
        let client = Self {
            dial_out,
            sessions: Arc::new(Mutex::new(IndexMap::new())),
            idle_sessions: Arc::new(Mutex::new(Vec::new())),
            session_counter: Arc::new(Mutex::new(0)),
            padding,
            idle_session_timeout,
            min_idle_sessions,
        };

        let idle_sessions = client.idle_sessions.clone();
        let idle_timeout = client.idle_session_timeout;
        let min_idle = client.min_idle_sessions;

        tokio::spawn(async move {
            let mut interval = interval(idle_session_check_interval);
            loop {
                interval.tick().await;
                Self::idle_cleanup(&idle_sessions, idle_timeout, min_idle).await;
            }
        });

        client
    }

    pub async fn create_stream(&self) -> Result<Arc<Session>, std::io::Error> {
        let mut last_error = None;
        for _ in 0..3 {
            let (session, seq) = self.find_or_create_session().await?;
            match session.open_stream().await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    log::warn!("Failed to open stream on session {seq}: {error}, retrying...");
                    let _ = session.close().await;
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| std::io::Error::other("Failed to create stream")))
    }

    async fn find_or_create_session(&self) -> Result<(Arc<Session>, u64), std::io::Error> {
        if let Some((session, seq)) = self.pick_session_from_idle_pool().await {
            self.spawn_idle_waiter(session.clone(), seq);
            return Ok((session, seq));
        }

        let (session, seq) = self.create_session().await?;
        self.spawn_idle_waiter(session.clone(), seq);
        Ok((session, seq))
    }

    fn spawn_idle_waiter(&self, session: Arc<Session>, seq: u64) {
        let idle_sessions = self.idle_sessions.clone();
        tokio::spawn(async move {
            session.wait_for_idle().await;
            if !session.is_closed().await {
                log::debug!("Session {seq} is now idle, adding back to idle pool");
                idle_sessions.lock().await.push((seq, session, Instant::now()));
            }
        });
    }

    async fn pick_session_from_idle_pool(&self) -> Option<(Arc<Session>, u64)> {
        let mut idle_sessions = self.idle_sessions.lock().await;
        while let Some((seq, session, idle_since)) = idle_sessions.pop() {
            if session.is_closed().await {
                continue;
            }

            if idle_since.elapsed() >= self.idle_session_timeout {
                log::debug!("Dropping stale idle session {seq} before reuse");
                let _ = session.close().await;
                continue;
            }

            // Debug: reusing idle session
            let ptr = Arc::as_ptr(&session) as usize;
            log::debug!("Client: reusing idle session seq={} ptr=0x{:x}", seq, ptr);
            return Some((session, seq));
        }
        None
    }

    async fn create_session(&self) -> Result<(Arc<Session>, u64), std::io::Error> {
        log::info!("Client: creating new session (dial out)");
        let conn = match (self.dial_out)().await {
            Ok(c) => {
                log::debug!("Client: dial out succeeded");
                c
            }
            Err(e) => {
                log::warn!("Client: dial out failed: {e}");
                return Err(e);
            }
        };
        let session = Arc::new(new_client_session(conn, self.padding.clone()).await);
        session.ensure_started().await?;

        let seq = {
            let mut counter = self.session_counter.lock().await;
            *counter += 1;
            *counter
        };

        self.sessions.lock().await.insert(seq, session.clone());
        // Debug: record created session seq and pointer
        let ptr = Arc::as_ptr(&session) as usize;
        log::debug!("Client: created session seq={} ptr=0x{:x}", seq, ptr);

        let session_clone = session.clone();
        let sessions = self.sessions.clone();

        tokio::spawn(async move {
            let result = session_clone.run().await;
            log::debug!("Session {seq} ended: {result:?}");
            sessions.lock().await.swap_remove(&seq);
        });

        Ok((session, seq))
    }

    #[allow(clippy::type_complexity)]
    async fn idle_cleanup(idle_sessions: &Arc<Mutex<Vec<(u64, Arc<Session>, Instant)>>>, timeout: Duration, min_idle: usize) {
        let mut idles = idle_sessions.lock().await;
        let now = Instant::now();
        let mut active_count = 0;
        let mut to_remove = Vec::new();

        for (index, (_, _session, idle_since)) in idles.iter().enumerate() {
            if now.duration_since(*idle_since) < timeout {
                active_count += 1;
                continue;
            }

            if active_count < min_idle {
                active_count += 1;
                continue;
            }

            to_remove.push(index);
        }

        for &index in to_remove.iter().rev() {
            if index < idles.len() {
                let (_, session, _) = idles.swap_remove(index);
                let _ = session.close().await;
            }
        }
    }

    pub async fn close(&self) -> Result<(), std::io::Error> {
        let sessions = self.sessions.lock().await;
        for session in sessions.values() {
            let _ = session.close().await;
        }
        Ok(())
    }
}
