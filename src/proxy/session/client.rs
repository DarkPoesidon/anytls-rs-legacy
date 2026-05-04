use crate::DialOutFunc;
use crate::core::PaddingFactory;
use crate::proxy::session::Session;
use crate::runtime::new_client_session;
use indexmap::IndexMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;

pub struct Client {
    dial_out: DialOutFunc,
    sessions: Arc<Mutex<IndexMap<u64, Arc<Session>>>>,
    #[allow(clippy::type_complexity)]
    idle_sessions: Arc<Mutex<IndexMap<u64, (Arc<Session>, Instant)>>>,
    idle_pool_notify: Arc<tokio::sync::Notify>,
    session_seq_number: AtomicU64,
    closed_flag: Arc<AtomicBool>,
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
            idle_sessions: Arc::new(Mutex::new(IndexMap::new())),
            idle_pool_notify: Arc::new(tokio::sync::Notify::new()),
            session_seq_number: AtomicU64::new(0),
            closed_flag: Arc::new(AtomicBool::new(false)),
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
        if self.closed_flag.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Client closed"));
        }

        let mut last_error = None;
        for _ in 0..3 {
            if self.closed_flag.load(Ordering::SeqCst) {
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Client closed"));
            }

            let (session, seq) = self.find_or_create_session().await?;
            match session.open_stream().await {
                Ok(stream) => {
                    self.spawn_idle_waiter(session.clone(), seq);
                    return Ok(stream);
                }
                Err(error) => {
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

        if let Some((session, seq)) = self.pick_session_from_idle_pool().await {
            return Ok((session, seq));
        }

        if self.closed_flag.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Client closed"));
        }

        let (session, seq) = self.create_session().await?;
        Ok((session, seq))
    }

    fn spawn_idle_waiter(&self, session: Arc<Session>, seq: u64) {
        let idle_sessions = self.idle_sessions.clone();
        let idle_pool_notify = self.idle_pool_notify.clone();
        tokio::spawn(async move {
            let ptr = Arc::as_ptr(&session) as usize;
            // Fast-path: if session already closed or already idle, handle immediately
            if session.is_terminated().await {
                log::trace!("Client: idle waiter sees terminated session seq={} ptr=0x{:x}", seq, ptr);
                return;
            }

            if !session.is_stream_open().await {
                let mut idles = idle_sessions.lock().await;
                if idles.contains_key(&seq) {
                    log::trace!("Client: idle waiter found session already pooled seq={} ptr=0x{:x}", seq, ptr);
                    return;
                }
                log::trace!("Client: idle waiter pooled session immediately seq={} ptr=0x{:x}", seq, ptr);
                idles.insert(seq, (session.clone(), Instant::now()));
                idle_pool_notify.notify_waiters();
                return;
            }

            // Otherwise wait for the idle notification
            log::trace!("Client: idle waiter waiting for session seq={} ptr=0x{:x}", seq, ptr);
            session.wait_for_idle().await;
            log::trace!("Client: idle waiter woke for session seq={} ptr=0x{:x}", seq, ptr);

            if session.is_terminated().await {
                log::trace!("Client: idle waiter woke to terminated session seq={} ptr=0x{:x}", seq, ptr);
                return;
            }

            // Double-check the logical stream is actually closed (idle).
            // This avoids a race where the session signals idle but another
            // task opens the stream again before we push it back into the pool.
            if session.is_stream_open().await {
                log::trace!("Client: idle waiter woke but stream reopened seq={} ptr=0x{:x}", seq, ptr);
                return;
            }

            let mut idles = idle_sessions.lock().await;
            if idles.contains_key(&seq) {
                log::trace!("Client: idle waiter found session pooled after wake seq={} ptr=0x{:x}", seq, ptr);
                return;
            }

            log::trace!("Client: idle waiter returning session to pool seq={} ptr=0x{:x}", seq, ptr);
            idles.insert(seq, (session, Instant::now()));
            idle_pool_notify.notify_waiters();
        });
    }

    async fn pick_session_from_idle_pool(&self) -> Option<(Arc<Session>, u64)> {
        loop {
            let candidate = {
                let mut idle_sessions = self.idle_sessions.lock().await;
                if idle_sessions.is_empty() {
                    None
                } else {
                    let last_index = idle_sessions.len() - 1;
                    idle_sessions.swap_remove_index(last_index)
                }
            };

            let (seq, (session, idle_since)) = candidate?;

            if session.is_terminated().await {
                continue;
            }

            if idle_since.elapsed() >= self.idle_session_timeout {
                log::trace!("Dropping stale idle session {seq} before reuse");
                let _ = session.terminate().await;
                continue;
            }

            // Debug: reusing idle session
            let ptr = Arc::as_ptr(&session) as usize;
            log::trace!("Client: reusing idle session seq={} ptr=0x{:x}", seq, ptr);
            return Some((session, seq));
        }
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

        self.sessions.lock().await.insert(seq, session.clone());
        // Debug: record created session seq and pointer
        let ptr = Arc::as_ptr(&session) as usize;
        log::trace!("Client: created session seq={} ptr=0x{:x}", seq, ptr);

        let session_clone = session.clone();
        let sessions = self.sessions.clone();
        let idle_pool_notify = self.idle_pool_notify.clone();

        tokio::spawn(async move {
            let result = session_clone.run().await;
            log::debug!("Session {seq} ended: {result:?}");
            sessions.lock().await.swap_remove(&seq);
            idle_pool_notify.notify_waiters();
        });

        Ok((session, seq))
    }

    #[allow(clippy::type_complexity)]
    async fn idle_cleanup(idle_sessions: &Arc<Mutex<IndexMap<u64, (Arc<Session>, Instant)>>>, timeout: Duration, min_idle: usize) {
        let mut to_terminate: Vec<Arc<Session>> = Vec::new();
        let mut idles = idle_sessions.lock().await;
        let now = Instant::now();

        // If we have <= min_idle entries, don't remove any.
        if idles.len() <= min_idle {
            return;
        }

        // Collect indices of entries that are timed out (oldest first because
        // IndexMap preserves insertion order). We'll remove oldest timed-out
        // entries but ensure we keep at least `min_idle` entries.
        let mut timed_out_indices: Vec<usize> = Vec::new();
        for index in 0..idles.len() {
            if let Some((_seq, (_session, idle_since))) = idles.get_index(index)
                && now.duration_since(*idle_since) >= timeout
            {
                timed_out_indices.push(index);
            }
        }

        if timed_out_indices.is_empty() {
            return;
        }

        // We can remove at most `idles.len() - min_idle` entries overall.
        let max_removable = idles.len().saturating_sub(min_idle);
        let remove_count = std::cmp::min(max_removable, timed_out_indices.len());

        // Remove the oldest timed-out entries first: take the first `remove_count`
        // indices from `timed_out_indices` (they are already in ascending order),
        // and remove by index in reverse to keep indices valid while removing.
        let to_remove = &timed_out_indices[..remove_count];
        for &index in to_remove.iter().rev() {
            if let Some((_seq, (session, _))) = idles.swap_remove_index(index) {
                to_terminate.push(session);
            }
        }

        drop(idles);

        for session in to_terminate {
            let _ = session.terminate().await;
        }
    }

    pub async fn close(&self) -> Result<(), std::io::Error> {
        if self.closed_flag.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let mut sessions_to_terminate: Vec<Arc<Session>> = Vec::new();

        {
            let mut sessions = self.sessions.lock().await;
            sessions_to_terminate.extend(sessions.values().cloned());
            sessions.clear();
        }

        {
            let mut idle_sessions = self.idle_sessions.lock().await;
            sessions_to_terminate.extend(idle_sessions.values().map(|(session, _)| session.clone()));
            idle_sessions.clear();
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
    use crate::core::{Command, Frame};
    use crate::proxy::session::DEFAULT_SID;
    use crate::runtime::{DefaultPaddingFactory, ProtocolHost};
    use crate::{AsyncReadWrite, DialOutFunc};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;
    use tokio::io::duplex;
    use tokio::task::yield_now;
    use tokio::time::timeout;

    #[tokio::test]
    async fn local_fin_does_not_return_session_to_idle_pool_before_remote_fin() {
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
        );

        let stream = client.create_stream().await.expect("stream should be created");
        stream
            .write_frame(Frame::new(Command::Fin, DEFAULT_SID))
            .await
            .expect("local FIN should be sent");
        stream
            .mark_local_stream_closed(DEFAULT_SID)
            .await
            .expect("local FIN should close only the local half");
        yield_now().await;

        assert!(
            client.idle_sessions.lock().await.is_empty(),
            "local FIN alone must not make the session reusable"
        );

        stream
            .close_logical_stream(DEFAULT_SID)
            .await
            .expect("remote FIN should close the logical stream");

        let (reused, reused_seq) = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(session) = client.pick_session_from_idle_pool().await {
                    break session;
                }
                yield_now().await;
            }
        })
        .await
        .expect("session should become idle after remote FIN");

        assert_eq!(reused_seq, 0, "the first session should be returned to the idle pool");
        assert!(
            !reused.is_stream_open().await,
            "reused session should still be idle when removed from the idle pool"
        );
    }

    #[tokio::test]
    async fn active_session_without_idle_pool_does_not_delay_new_session_creation() {
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
        );

        let _first_stream = client.create_stream().await.expect("first stream should be created");
        yield_now().await;
        assert!(client.idle_sessions.lock().await.is_empty(), "first stream should still be active");

        let (second_session, second_seq) = timeout(Duration::from_millis(50), client.find_or_create_session())
            .await
            .expect("new session creation should not wait for idle pool reuse")
            .expect("new session should be created successfully");

        assert_eq!(second_seq, 1, "a new live session should be created instead of waiting for reuse");
        assert!(
            !second_session.is_stream_open().await,
            "new session should not have an active logical stream yet"
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
        );

        let stream = client.create_stream().await.expect("stream should be created");
        stream
            .close_logical_stream(DEFAULT_SID)
            .await
            .expect("remote FIN should close only the remote half");

        let mut buf = [0u8; 1];
        let eof_len = timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("remote FIN should wake the reader")
            .expect("reader should observe EOF after remote FIN");
        assert_eq!(eof_len, 0, "remote FIN should surface as EOF to the local reader");

        yield_now().await;
        assert!(
            client.idle_sessions.lock().await.is_empty(),
            "remote FIN alone must not make the session reusable"
        );

        stream
            .write_frame(Frame::new(Command::Fin, DEFAULT_SID))
            .await
            .expect("local FIN should be sent after observing remote EOF");
        stream
            .mark_local_stream_closed(DEFAULT_SID)
            .await
            .expect("local FIN should close the remaining local half");

        let (reused, reused_seq) = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(session) = client.pick_session_from_idle_pool().await {
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
}
