#[cfg(feature = "client")]
pub mod client;
pub mod inner;

// stream module removed; single-session model
//
// Historically `sid` was a per-session logical stream identifier used for
// multiplexing multiple logical streams over a single underlying connection.
// Each session allocated `sid` values starting at `1` (with `1` commonly
// serving as the initial/reserved stream) and allocated larger ids for new
// logical streams. After removing multiplexing, this implementation fixes
// the single logical stream id to `DEFAULT_SID = 1` so the rest of the
// protocol machinery can continue to reference a stable sid.
pub const DEFAULT_SID: u32 = 1;

use crate::AsyncReadWrite;
use crate::core::PaddingFactory;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "client")]
pub use client::Client;
pub use inner::Session;

#[cfg(feature = "client")]
pub async fn new_client_session(conn: Box<dyn AsyncReadWrite>, padding: Arc<RwLock<PaddingFactory>>) -> Session {
    crate::runtime::new_client_session(conn, padding).await
}

#[cfg(feature = "server")]
pub async fn new_server_session(
    conn: Box<dyn AsyncReadWrite>,
    on_new_session: Box<dyn Fn(Arc<Session>) + Send + Sync>,
    padding: Arc<RwLock<PaddingFactory>>,
) -> Session {
    crate::runtime::new_server_session(conn, on_new_session, padding).await
}
