//! Panel-facing node control surface: a multi-user registry plus the loopback
//! management API a supervising panel drives it through.
//!
//! This is an alternative to [`crate::panel_sync`], which polls an sspanel-style
//! webapi and identifies users by a `client_id` UUID carried in the auth
//! padding. That scheme only works with clients that know to send the UUID, and
//! it cannot be trusted for accounting because every user shares one password.
//! Here the panel pushes the user set to the node instead, each user holds its
//! own password, and identity comes from the auth bytes every AnyTLS client
//! already sends.

pub mod api;
pub mod users;

pub use api::{ApiConfig, StatsResponse, StatsUser, UsersPutBody, UsersPutEntry, collect_stats, serve};
pub use users::{AuthedUser, DenyReason, UserEntry, UserRegistry, UserSpec, hash_password};

use std::path::Path;

/// Load the boot-time user set from a JSON file shaped exactly like a
/// `PUT /users` body:
///
/// ```json
/// { "users": { "alice@example.com": { "password": "…", "quota_bytes": 0, "expires_unix": 0 } } }
/// ```
///
/// The node reads this once at startup so a restart serves its users again
/// immediately, without waiting for the panel to push. After that the file is
/// only advisory: the API is the live source of truth.
pub async fn load_users_file(path: &Path) -> std::io::Result<Vec<UserSpec>> {
    let content = tokio::fs::read(path).await?;
    let body: UsersPutBody = serde_json::from_slice(&content).map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
    Ok(body.into_specs())
}
