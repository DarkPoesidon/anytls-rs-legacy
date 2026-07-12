use crate::DialOutFunc;
use crate::core::PaddingFactory;
use crate::proxy::session::{Session, Stream};
use crate::runtime::new_client_session;
use indexmap::IndexMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;

type IdleSessionEntry = (Arc<Session>, Instant);

/// Tracks sessions that have fully gone idle and can be reused for the next stream.
struct IdleSessionPool {
    sessions: Mutex<IndexMap<u64, IdleSessionEntry>>,
}

impl IdleSessionPool {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(IndexMap::new()),
        }
    }

    async fn take_reusable(&self, idle_session_timeout: Duration) -> Option<(Arc<Session>, u64)> {
        loop {
            let candidate = {
                let mut sessions = self.sessions.lock().await;
                if sessions.is_empty() {
                    None
                } else {
                    let last_index = sessions.len() - 1;
                    sessions.swap_remove_index(last_index)
                }
            };

            let (seq, (session, idle_since)) = candidate?;

            if session.is_terminated().await {
                continue;
            }

            if idle_since.elapsed() >= idle_session_timeout {
                log::trace!("Dropping stale idle session {seq} before reuse");
                let _ = session.terminate().await;
                continue;
            }

            let ptr = Arc::as_ptr(&session) as usize;
            log::trace!("Client: reusing idle session seq={} ptr=0x{:x}", seq, ptr);
            return Some((session, seq));
        }
    }

    async fn return_session(&self, seq: u64, session: Arc<Session>) {
        let mut sessions = self.sessions.lock().await;
        if sessions.contains_key(&seq) {
            return;
        }

        let ptr = Arc::as_ptr(&session) as usize;
        log::trace!("Client: returning session to idle pool seq={} ptr=0x{:x}", seq, ptr);
        sessions.insert(seq, (session, Instant::now()));
    }

    async fn cleanup_stale(&self, timeout: Duration, min_idle: usize) {
        let mut to_terminate: Vec<Arc<Session>> = Vec::new();
        let mut sessions = self.sessions.lock().await;
        let now = Instant::now();

        if sessions.len() <= min_idle {
            return;
        }

        let mut timed_out_indices: Vec<usize> = Vec::new();
        for index in 0..sessions.len() {
            if let Some((_seq, (_session, idle_since))) = sessions.get_index(index)
                && now.duration_since(*idle_since) >= timeout
            {
                timed_out_indices.push(index);
            }
        }

        if timed_out_indices.is_empty() {
            return;
        }

        let max_removable = sessions.len().saturating_sub(min_idle);
        let remove_count = std::cmp::min(max_removable, timed_out_indices.len());
        let to_remove = &timed_out_indices[..remove_count];
        for &index in to_remove.iter().rev() {
            if let Some((_seq, (session, _))) = sessions.swap_remove_index(index) {
                to_terminate.push(session);
            }
        }

        drop(sessions);

        for session in to_terminate {
            let _ = session.terminate().await;
        }
    }

    async fn drain(&self) -> Vec<Arc<Session>> {
        let mut sessions = self.sessions.lock().await;
        let drained = sessions.values().map(|(session, _)| session.clone()).collect();
        sessions.clear();
        drained
    }

    #[allow(dead_code)]
    async fn is_empty(&self) -> bool {
        self.sessions.lock().await.is_empty()
    }
}

pub struct Client {
    dial_out: DialOutFunc,
    active_sessions: Arc<Mutex<IndexMap<u64, Arc<Session>>>>,
    idle_session_pool: Arc<IdleSessionPool>,
    session_seq_number: AtomicU64,
    closed_flag: Arc<AtomicBool>,
    padding: Arc<RwLock<PaddingFactory>>,
    idle_session_timeout: Duration,
    min_idle_sessions: usize,
    max_streams_per_session: usize,
}

impl Client {
    pub fn new(
        dial_out: DialOutFunc,
        padding: Arc<RwLock<PaddingFactory>>,
        idle_session_check_interval: Duration,
        idle_session_timeout: Duration,
        min_idle_sessions: usize,
        max_streams_per_session: usize,
    ) -> Self {
        let client = Self {
            dial_out,
            active_sessions: Arc::new(Mutex::new(IndexMap::new())),
            idle_session_pool: Arc::new(IdleSessionPool::new()),
            session_seq_number: AtomicU64::new(0),
            closed_flag: Arc::new(AtomicBool::new(false)),
            padding,
            idle_session_timeout,
            min_idle_sessions,
            max_streams_per_session: max_streams_per_session.max(1),
        };

        let idle_session_pool = client.idle_session_pool.clone();
        let idle_timeout = client.idle_session_timeout;
        let min_idle = client.min_idle_sessions;

        tokio::spawn(async move {
            let mut interval = interval(idle_session_check_interval);
            loop {
                interval.tick().await;
                idle_session_pool.cleanup_stale(idle_timeout, min_idle).await;
            }
        });

        client
    }

    pub async fn create_stream(&self) -> Result<Arc<Stream>, std::io::Error> {
        if self.closed_flag.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Client closed"));
        }

        let mut last_error = None;
        for _ in 0..3 {
            if self.closed_flag.load(Ordering::SeqCst) {
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Client closed"));
            }

            let (session, seq) = self.find_or_create_session().await?;
            match session.open_stream(self.max_streams_per_session).await {
                Ok(stream) => {
                    self.spawn_idle_return_task(session.clone(), seq);
                    return Ok(stream);
                }
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        last_error = Some(error);
                        continue;
                    }
                    log::warn!("Failed to open stream on session {seq}: {error}, retrying...");
                    let _ = session.terminate().await;
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| std::io::Error::other("Failed to create stream")))
    }

    async fn find_or_create_session(&self) -> Result<(Arc<Session>, u64), std::io::Error> {
        if self.closed_flag.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Client closed"));
        }

        if let Some((session, seq)) = self.take_reusable_session().await {
            return Ok((session, seq));
        }

        let active_sessions = {
            let sessions = self.active_sessions.lock().await;
            sessions.iter().map(|(seq, session)| (*seq, session.clone())).collect::<Vec<_>>()
        };
        for (seq, session) in active_sessions {
            if !session.is_terminated().await && session.has_stream_capacity(self.max_streams_per_session).await {
                return Ok((session, seq));
            }
        }

        if self.closed_flag.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Client closed"));
        }

        let (session, seq) = self.create_session().await?;
        Ok((session, seq))
    }

    fn spawn_idle_return_task(&self, session: Arc<Session>, seq: u64) {
        let idle_session_pool = self.idle_session_pool.clone();
        tokio::spawn(async move {
            let ptr = Arc::as_ptr(&session) as usize;
            if session.is_terminated().await {
                log::trace!("Client: idle waiter sees terminated session seq={} ptr=0x{:x}", seq, ptr);
                return;
            }

            if !session.is_stream_open().await {
                idle_session_pool.return_session(seq, session.clone()).await;
                return;
            }

            log::trace!("Client: idle waiter waiting for session seq={} ptr=0x{:x}", seq, ptr);
            session.wait_for_idle().await;
            log::trace!("Client: idle waiter woke for session seq={} ptr=0x{:x}", seq, ptr);

            if session.is_terminated().await {
                log::trace!("Client: idle waiter woke to terminated session seq={} ptr=0x{:x}", seq, ptr);
                return;
            }

            if session.is_stream_open().await {
                log::trace!("Client: idle waiter woke but stream reopened seq={} ptr=0x{:x}", seq, ptr);
                return;
            }

            idle_session_pool.return_session(seq, session).await;
        });
    }

    async fn take_reusable_session(&self) -> Option<(Arc<Session>, u64)> {
        self.idle_session_pool.take_reusable(self.idle_session_timeout).await
    }

    async fn create_session(&self) -> Result<(Arc<Session>, u64), std::io::Error> {
        log::debug!("Client: creating new session (dial out)");
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

        if self.closed_flag.load(Ordering::SeqCst) {
            let _ = session.terminate().await;
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Client closed"));
        }

        // Use fetch_add to wrap to 0 after u64::MAX.
        let seq = { self.session_seq_number.fetch_add(1, Ordering::SeqCst) };

        self.active_sessions.lock().await.insert(seq, session.clone());
        // Debug: record created session seq and pointer
        let ptr = Arc::as_ptr(&session) as usize;
        log::trace!("Client: created session seq={} ptr=0x{:x}", seq, ptr);

        let session_clone = session.clone();
        let sessions = self.active_sessions.clone();

        tokio::spawn(async move {
            let result = session_clone.run().await;
            log::debug!("Session {seq} ended: {result:?}");
            sessions.lock().await.swap_remove(&seq);
        });

        Ok((session, seq))
    }

    pub async fn close(&self) -> Result<(), std::io::Error> {
        if self.closed_flag.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let mut sessions_to_terminate: Vec<Arc<Session>> = Vec::new();

        {
            let mut sessions = self.active_sessions.lock().await;
            sessions_to_terminate.extend(sessions.values().cloned());
            sessions.clear();
        }

        {
            sessions_to_terminate.extend(self.idle_session_pool.drain().await);
        }

        for session in sessions_to_terminate {
            let _ = session.terminate().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use crate::runtime::DefaultPaddingFactory;
    use crate::{AsyncReadWrite, DialOutFunc};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;
    use tokio::io::duplex;
    use tokio::task::yield_now;
    use tokio::time::timeout;

    #[tokio::test]
    async fn closing_last_stream_returns_session_to_idle_pool() {
        let peers = Arc::new(StdMutex::new(Vec::new()));
        let dial_out: DialOutFunc = {
            let peers = peers.clone();
            Box::new(move || {
                let peers = peers.clone();
                Box::pin(async move {
                    let (client_io, peer_io) = duplex(1024);
                    peers.lock().expect("peer store lock poisoned").push(peer_io);
                    Ok(Box::new(client_io) as Box<dyn AsyncReadWrite>)
                })
            })
        };

        let client = Client::new(
            dial_out,
            DefaultPaddingFactory::load(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            0,
            5,
        );

        let stream = client.create_stream().await.expect("stream should be created");
        stream.close().await.expect("stream should close");

        let (reused, reused_seq) = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(session) = client.take_reusable_session().await {
                    break session;
                }
                yield_now().await;
            }
        })
        .await
        .expect("session should become idle after its last stream closes");

        assert_eq!(reused_seq, 0, "the first session should be returned to the idle pool");
        assert!(
            !reused.is_stream_open().await,
            "reused session should still be idle when removed from the idle pool"
        );
    }

    #[tokio::test]
    async fn active_session_accepts_another_stream_without_dialing() {
        let peers = Arc::new(StdMutex::new(Vec::new()));
        let dial_out: DialOutFunc = {
            let peers = peers.clone();
            Box::new(move || {
                let peers = peers.clone();
                Box::pin(async move {
                    let (client_io, peer_io) = duplex(1024);
                    peers.lock().expect("peer store lock poisoned").push(peer_io);
                    Ok(Box::new(client_io) as Box<dyn AsyncReadWrite>)
                })
            })
        };

        let client = Client::new(
            dial_out,
            DefaultPaddingFactory::load(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            0,
            5,
        );

        let _first_stream = client.create_stream().await.expect("first stream should be created");
        yield_now().await;
        assert!(client.idle_session_pool.is_empty().await, "first stream should still be active");

        let (second_session, second_seq) = timeout(Duration::from_millis(50), client.find_or_create_session())
            .await
            .expect("new session creation should not wait for idle pool reuse")
            .expect("new session should be created successfully");

        assert_eq!(second_seq, 0, "a live session should be reused for another multiplexed stream");
        assert!(
            second_session.is_stream_open().await,
            "reused session should still contain the first active logical stream"
        );

        client.close().await.expect("client should close cleanly");
    }

    #[tokio::test]
    async fn remote_fin_does_not_return_session_to_idle_pool_before_local_fin() {
        let peers = Arc::new(StdMutex::new(Vec::new()));
        let dial_out: DialOutFunc = {
            let peers = peers.clone();
            Box::new(move || {
                let peers = peers.clone();
                Box::pin(async move {
                    let (client_io, peer_io) = duplex(1024);
                    peers.lock().expect("peer store lock poisoned").push(peer_io);
                    Ok(Box::new(client_io) as Box<dyn AsyncReadWrite>)
                })
            })
        };

        let client = Client::new(
            dial_out,
            DefaultPaddingFactory::load(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            0,
            5,
        );

        let stream = client.create_stream().await.expect("stream should be created");
        stream.close().await.expect("stream should close");

        let (reused, reused_seq) = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(session) = client.take_reusable_session().await {
                    break session;
                }
                yield_now().await;
            }
        })
        .await
        .expect("session should become idle after both halves close");

        assert_eq!(reused_seq, 0, "the first session should be returned to the idle pool");
        assert!(
            !reused.is_stream_open().await,
            "reused session should still be idle when removed from the idle pool"
        );
    }

    #[tokio::test]
    async fn stream_limit_opens_a_new_session_when_multiplexing_is_disabled() {
        let peers = Arc::new(StdMutex::new(Vec::new()));
        let dial_out: DialOutFunc = {
            let peers = peers.clone();
            Box::new(move || {
                let peers = peers.clone();
                Box::pin(async move {
                    let (client_io, peer_io) = duplex(1024);
                    peers.lock().expect("peer store lock poisoned").push(peer_io);
                    Ok(Box::new(client_io) as Box<dyn AsyncReadWrite>)
                })
            })
        };

        let client = Client::new(
            dial_out,
            DefaultPaddingFactory::load(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            0,
            1,
        );

        let _first = client.create_stream().await.expect("first stream should be created");
        let _second = client.create_stream().await.expect("second stream should be created");

        assert_eq!(
            peers.lock().expect("peer store lock poisoned").len(),
            2,
            "the limit should require a second session"
        );
        client.close().await.expect("client should close cleanly");
    }
}
