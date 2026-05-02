use crate::DialOutFunc;
use crate::core::PaddingFactory;
use crate::proxy::session::Session;
use crate::runtime::new_client_session;
use indexmap::IndexMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;

pub struct Client {
    dial_out: DialOutFunc,
    sessions: Arc<Mutex<IndexMap<u64, Arc<Session>>>>,
    #[allow(clippy::type_complexity)]
    idle_sessions: Arc<Mutex<IndexMap<u64, (Arc<Session>, Instant)>>>,
    session_seq_number: AtomicU64,
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
            session_seq_number: AtomicU64::new(0),
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
        if let Some((session, seq)) = self.pick_session_from_idle_pool().await {
            return Ok((session, seq));
        }

        let (session, seq) = self.create_session().await?;
        Ok((session, seq))
    }

    fn spawn_idle_waiter(&self, session: Arc<Session>, seq: u64) {
        let idle_sessions = self.idle_sessions.clone();
        tokio::spawn(async move {
            // Fast-path: if session already closed or already idle, handle immediately
            if session.is_terminated().await {
                return;
            }

            if !session.is_stream_open().await {
                let mut idles = idle_sessions.lock().await;
                if idles.contains_key(&seq) {
                    return;
                }
                idles.insert(seq, (session.clone(), Instant::now()));
                return;
            }

            // Otherwise wait for the idle notification
            session.wait_for_idle().await;

            if session.is_terminated().await {
                return;
            }

            // Double-check the logical stream is actually closed (idle).
            // This avoids a race where the session signals idle but another
            // task opens the stream again before we push it back into the pool.
            if session.is_stream_open().await {
                return;
            }

            let mut idles = idle_sessions.lock().await;
            if idles.contains_key(&seq) {
                return;
            }

            idles.insert(seq, (session, Instant::now()));
        });
    }

    async fn pick_session_from_idle_pool(&self) -> Option<(Arc<Session>, u64)> {
        let mut idle_sessions = self.idle_sessions.lock().await;
        while !idle_sessions.is_empty() {
            let last_index = idle_sessions.len() - 1;
            if let Some((seq, (session, idle_since))) = idle_sessions.swap_remove_index(last_index) {
                if session.is_terminated().await {
                    continue;
                }

                if idle_since.elapsed() >= self.idle_session_timeout {
                    log::debug!("Dropping stale idle session {seq} before reuse");
                    let _ = session.terminate().await;
                    continue;
                }

                // Debug: reusing idle session
                let ptr = Arc::as_ptr(&session) as usize;
                log::debug!("Client: reusing idle session seq={} ptr=0x{:x}", seq, ptr);
                return Some((session, seq));
            } else {
                break;
            }
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

        // Use fetch_add to wrap to 0 after u64::MAX.
        let seq = { self.session_seq_number.fetch_add(1, Ordering::SeqCst) };

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
    async fn idle_cleanup(idle_sessions: &Arc<Mutex<IndexMap<u64, (Arc<Session>, Instant)>>>, timeout: Duration, min_idle: usize) {
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
                let _ = session.terminate().await;
            }
        }
    }

    pub async fn close(&self) -> Result<(), std::io::Error> {
        let sessions = self.sessions.lock().await;
        for session in sessions.values() {
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
