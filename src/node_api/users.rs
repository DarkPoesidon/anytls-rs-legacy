//! Multi-user registry for panel-managed nodes.
//!
//! The stock server authenticates every connection against a single
//! `sha256(password)`, which makes per-user accounting impossible to trust: the
//! only per-user marker on the wire is the `client_id` carried in the auth
//! padding, and any holder of the shared password can send any UUID. Here each
//! user instead owns a distinct password, so the 32 auth bytes a client already
//! sends *are* the identity, and no protocol change is needed - stock AnyTLS
//! clients (sing-box, mihomo, Shadowrocket) work unmodified.
//!
//! Counters live in atomics on the per-user entry, and a connection resolves its
//! entry once at auth time. The relay hot path is therefore a lock-free
//! `fetch_add` rather than a lock on one process-wide mutex.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// Length of the SHA-256 password digest a client sends as its first auth bytes.
pub const PASSWORD_HASH_LEN: usize = 32;

pub type PasswordHash = [u8; PASSWORD_HASH_LEN];

/// Hash a password the way the AnyTLS auth preamble does.
pub fn hash_password(password: &str) -> PasswordHash {
    Sha256::digest(password.as_bytes()).into()
}

/// One user as described by the panel: its credential and its limits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSpec {
    /// Panel-side identity. This is the key the panel attributes traffic to;
    /// 3x-ui uses the client email.
    pub email: String,
    pub password: String,
    /// Total (up + down) byte allowance, counted from the last quota reset.
    /// Zero means unlimited.
    #[serde(default)]
    pub quota_bytes: u64,
    /// Unix seconds after which the user is refused. Zero means never.
    #[serde(default)]
    pub expires_unix: i64,
}

/// Why a user may not pass traffic right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// The user was removed from the registry, or its password was replaced.
    Revoked,
    /// The user's expiry timestamp is in the past.
    Expired,
    /// The user has spent its byte allowance.
    QuotaExceeded,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DenyReason::Revoked => write!(f, "revoked"),
            DenyReason::Expired => write!(f, "expired"),
            DenyReason::QuotaExceeded => write!(f, "quota exceeded"),
        }
    }
}

/// Live state of one user. Shared between the management API, the stats
/// scraper, and every connection the user has open.
#[derive(Debug)]
pub struct UserEntry {
    email: String,
    /// Bumped whenever the user's password is replaced, so sessions
    /// authenticated with the superseded password can notice and drop.
    generation: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    connections: AtomicI64,
    quota_bytes: AtomicU64,
    /// Value of `up + down` at the last quota reset; quota is measured from here
    /// so the reported counters stay monotonic for the panel's delta maths.
    quota_base: AtomicU64,
    expires_unix: AtomicI64,
    revoked: AtomicBool,
}

impl UserEntry {
    fn new(spec: &UserSpec) -> Self {
        Self {
            email: spec.email.clone(),
            generation: AtomicU64::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            connections: AtomicI64::new(0),
            quota_bytes: AtomicU64::new(spec.quota_bytes),
            quota_base: AtomicU64::new(0),
            expires_unix: AtomicI64::new(spec.expires_unix),
            revoked: AtomicBool::new(false),
        }
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn record_up(&self, bytes: u64) {
        self.up.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_down(&self, bytes: u64) {
        self.down.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn bytes_up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }

    pub fn connections(&self) -> i64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Bytes counted against the current quota window.
    pub fn quota_used(&self) -> u64 {
        let total = self.bytes_up().saturating_add(self.bytes_down());
        total.saturating_sub(self.quota_base.load(Ordering::Relaxed))
    }

    pub fn quota_bytes(&self) -> u64 {
        self.quota_bytes.load(Ordering::Relaxed)
    }

    pub fn expires_unix(&self) -> i64 {
        self.expires_unix.load(Ordering::Relaxed)
    }

    /// Start a new quota window at the current counters, leaving the reported
    /// totals untouched.
    pub fn reset_quota(&self) {
        let total = self.bytes_up().saturating_add(self.bytes_down());
        self.quota_base.store(total, Ordering::Relaxed);
    }

    fn apply_limits(&self, spec: &UserSpec) {
        self.quota_bytes.store(spec.quota_bytes, Ordering::Relaxed);
        self.expires_unix.store(spec.expires_unix, Ordering::Relaxed);
    }

    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    /// Check the user against every limit, at the given wall-clock time.
    pub fn deny_reason_at(&self, now_unix: i64) -> Option<DenyReason> {
        if self.revoked.load(Ordering::Acquire) {
            return Some(DenyReason::Revoked);
        }
        let expires = self.expires_unix();
        if expires > 0 && now_unix >= expires {
            return Some(DenyReason::Expired);
        }
        let quota = self.quota_bytes();
        if quota > 0 && self.quota_used() >= quota {
            return Some(DenyReason::QuotaExceeded);
        }
        None
    }

    pub fn deny_reason(&self) -> Option<DenyReason> {
        self.deny_reason_at(now_unix())
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// A user resolved at authentication time, held for the life of one connection.
///
/// Holding this keeps the user's connection count accurate: the count is
/// decremented when the guard drops, however the connection ended.
#[derive(Debug)]
pub struct AuthedUser {
    entry: Arc<UserEntry>,
    /// Generation observed at auth time. A password change moves the entry's
    /// generation past this, which retires the connection.
    generation: u64,
}

impl AuthedUser {
    fn new(entry: Arc<UserEntry>) -> Self {
        let generation = entry.generation();
        entry.connections.fetch_add(1, Ordering::Relaxed);
        Self { entry, generation }
    }

    pub fn email(&self) -> &str {
        self.entry.email()
    }

    pub fn record_up(&self, bytes: u64) {
        self.entry.record_up(bytes);
    }

    pub fn record_down(&self, bytes: u64) {
        self.entry.record_down(bytes);
    }

    /// Why this connection must stop, or `None` while it may continue. Called
    /// once per second by the relay loops, so it stays lock-free.
    pub fn deny_reason(&self) -> Option<DenyReason> {
        if self.entry.generation() != self.generation {
            return Some(DenyReason::Revoked);
        }
        self.entry.deny_reason()
    }
}

impl Drop for AuthedUser {
    fn drop(&mut self) {
        self.entry.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
struct Index {
    by_email: HashMap<String, Arc<UserEntry>>,
    by_hash: HashMap<PasswordHash, Arc<UserEntry>>,
}

/// The set of users this node serves, replaceable in place by the panel.
#[derive(Debug, Default)]
pub struct UserRegistry {
    index: RwLock<Index>,
}

impl UserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_users(specs: &[UserSpec]) -> Self {
        let registry = Self::new();
        registry.replace(specs);
        registry
    }

    /// Resolve the 32 auth bytes a client sent to a usable user, or `None` when
    /// they match nobody or the matched user may not pass traffic.
    pub fn authenticate(&self, password_hash: &[u8]) -> Option<AuthedUser> {
        let hash: PasswordHash = password_hash.try_into().ok()?;
        let entry = self.index.read().by_hash.get(&hash).cloned()?;
        if let Some(reason) = entry.deny_reason() {
            log::debug!("rejected user {}: {reason}", entry.email());
            return None;
        }
        Some(AuthedUser::new(entry))
    }

    /// Replace the whole user set.
    ///
    /// Users that keep their password keep their entry, and therefore their
    /// counters and their live connections. A re-keyed user keeps its counters
    /// but its existing connections are retired, and a user that disappears from
    /// the set is revoked outright. This mirrors what the panel expects of a
    /// sidecar: adding or editing one client must not disturb the others.
    pub fn replace(&self, specs: &[UserSpec]) {
        let mut index = self.index.write();
        let mut by_email: HashMap<String, Arc<UserEntry>> = HashMap::with_capacity(specs.len());
        let mut by_hash: HashMap<PasswordHash, Arc<UserEntry>> = HashMap::with_capacity(specs.len());

        for spec in specs {
            if spec.email.is_empty() || spec.password.is_empty() {
                log::warn!("ignoring user entry with empty email or password: {}", spec.email);
                continue;
            }
            let hash = hash_password(&spec.password);
            if by_hash.contains_key(&hash) {
                log::warn!("ignoring user {}: its password collides with another user's", spec.email);
                continue;
            }
            let entry = match index.by_email.get(&spec.email) {
                Some(existing) => {
                    existing.apply_limits(spec);
                    // A password change retires the sessions opened with the old
                    // one, without losing what the user has already spent.
                    let rekeyed = !index.by_hash.get(&hash).is_some_and(|e| Arc::ptr_eq(e, existing));
                    if rekeyed {
                        existing.generation.fetch_add(1, Ordering::AcqRel);
                    }
                    existing.clone()
                }
                None => Arc::new(UserEntry::new(spec)),
            };
            by_email.insert(spec.email.clone(), entry.clone());
            by_hash.insert(hash, entry);
        }

        for (email, entry) in index.by_email.iter() {
            if !by_email.contains_key(email) {
                entry.revoke();
            }
        }

        index.by_email = by_email;
        index.by_hash = by_hash;
    }

    pub fn get(&self, email: &str) -> Option<Arc<UserEntry>> {
        self.index.read().by_email.get(email).cloned()
    }

    pub fn entries(&self) -> Vec<Arc<UserEntry>> {
        self.index.read().by_email.values().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.index.read().by_email.is_empty()
    }

    pub fn len(&self) -> usize {
        self.index.read().by_email.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(email: &str, password: &str) -> UserSpec {
        UserSpec {
            email: email.to_string(),
            password: password.to_string(),
            quota_bytes: 0,
            expires_unix: 0,
        }
    }

    #[test]
    fn authenticates_each_user_by_its_own_password() {
        let registry = UserRegistry::with_users(&[spec("a@x", "pw-a"), spec("b@x", "pw-b")]);

        let a = registry.authenticate(&hash_password("pw-a")).expect("user a");
        let b = registry.authenticate(&hash_password("pw-b")).expect("user b");
        assert_eq!(a.email(), "a@x");
        assert_eq!(b.email(), "b@x");
        assert!(registry.authenticate(&hash_password("pw-c")).is_none());
    }

    #[test]
    fn traffic_is_attributed_per_user() {
        let registry = UserRegistry::with_users(&[spec("a@x", "pw-a"), spec("b@x", "pw-b")]);
        registry.authenticate(&hash_password("pw-a")).unwrap().record_up(100);
        registry.authenticate(&hash_password("pw-b")).unwrap().record_down(70);

        assert_eq!(registry.get("a@x").unwrap().bytes_up(), 100);
        assert_eq!(registry.get("a@x").unwrap().bytes_down(), 0);
        assert_eq!(registry.get("b@x").unwrap().bytes_down(), 70);
    }

    #[test]
    fn connection_count_follows_guard_lifetime() {
        let registry = UserRegistry::with_users(&[spec("a@x", "pw-a")]);
        let entry = registry.get("a@x").unwrap();
        assert_eq!(entry.connections(), 0);

        let first = registry.authenticate(&hash_password("pw-a")).unwrap();
        let second = registry.authenticate(&hash_password("pw-a")).unwrap();
        assert_eq!(entry.connections(), 2);

        drop(first);
        assert_eq!(entry.connections(), 1);
        drop(second);
        assert_eq!(entry.connections(), 0);
    }

    #[test]
    fn quota_denies_once_spent_and_reset_reopens_without_rewinding_totals() {
        let mut s = spec("a@x", "pw-a");
        s.quota_bytes = 1000;
        let registry = UserRegistry::with_users(&[s]);

        let session = registry.authenticate(&hash_password("pw-a")).unwrap();
        session.record_up(600);
        session.record_down(300);
        assert_eq!(session.deny_reason(), None);
        session.record_down(200);
        assert_eq!(session.deny_reason(), Some(DenyReason::QuotaExceeded));
        assert!(registry.authenticate(&hash_password("pw-a")).is_none());

        registry.get("a@x").unwrap().reset_quota();
        assert_eq!(session.deny_reason(), None);
        // Totals stay monotonic so the panel's delta accounting is unaffected.
        assert_eq!(registry.get("a@x").unwrap().bytes_up(), 600);
        assert_eq!(registry.get("a@x").unwrap().bytes_down(), 500);
    }

    #[test]
    fn expiry_denies_authentication_and_live_sessions() {
        let mut s = spec("a@x", "pw-a");
        s.expires_unix = now_unix() + 3600;
        let registry = UserRegistry::with_users(&[s.clone()]);
        let session = registry.authenticate(&hash_password("pw-a")).unwrap();
        assert_eq!(session.deny_reason(), None);

        s.expires_unix = now_unix() - 1;
        registry.replace(&[s]);
        assert_eq!(session.deny_reason(), Some(DenyReason::Expired));
        assert!(registry.authenticate(&hash_password("pw-a")).is_none());
    }

    #[test]
    fn replace_keeps_untouched_users_and_revokes_removed_ones() {
        let registry = UserRegistry::with_users(&[spec("a@x", "pw-a"), spec("b@x", "pw-b")]);
        let a_session = registry.authenticate(&hash_password("pw-a")).unwrap();
        let b_session = registry.authenticate(&hash_password("pw-b")).unwrap();
        a_session.record_up(500);

        // b is dropped, a is left alone, c is added.
        registry.replace(&[spec("a@x", "pw-a"), spec("c@x", "pw-c")]);

        assert_eq!(a_session.deny_reason(), None, "an untouched user keeps its live sessions");
        assert_eq!(registry.get("a@x").unwrap().bytes_up(), 500, "and its counters");
        assert_eq!(b_session.deny_reason(), Some(DenyReason::Revoked));
        assert!(registry.authenticate(&hash_password("pw-b")).is_none());
        assert!(registry.authenticate(&hash_password("pw-c")).is_some());
    }

    #[test]
    fn rekeying_retires_old_sessions_but_keeps_counters() {
        let registry = UserRegistry::with_users(&[spec("a@x", "pw-a")]);
        let old_session = registry.authenticate(&hash_password("pw-a")).unwrap();
        old_session.record_down(400);

        registry.replace(&[spec("a@x", "pw-new")]);

        assert_eq!(old_session.deny_reason(), Some(DenyReason::Revoked));
        assert!(registry.authenticate(&hash_password("pw-a")).is_none());
        let new_session = registry.authenticate(&hash_password("pw-new")).unwrap();
        assert_eq!(new_session.deny_reason(), None);
        assert_eq!(registry.get("a@x").unwrap().bytes_down(), 400);
    }

    #[test]
    fn duplicate_passwords_are_refused_so_traffic_is_never_misattributed() {
        let registry = UserRegistry::with_users(&[spec("a@x", "same"), spec("b@x", "same")]);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.authenticate(&hash_password("same")).unwrap().email(), "a@x");
    }
}
