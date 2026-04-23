#[cfg(feature = "client")]
pub mod client;
pub mod inner;
pub mod stream;

use crate::AsyncReadWrite;
use crate::core::PaddingFactory;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "client")]
pub use client::Client;
pub use inner::Session;
pub use stream::Stream;

#[cfg(feature = "client")]
pub async fn new_client_session(conn: Box<dyn AsyncReadWrite>, padding: Arc<RwLock<PaddingFactory>>) -> Session {
    crate::runtime::new_client_session(conn, padding).await
}

#[cfg(feature = "server")]
pub async fn new_server_session(
    conn: Box<dyn AsyncReadWrite>,
    on_new_stream: Box<dyn Fn(Arc<Stream>) + Send + Sync>,
    padding: Arc<RwLock<PaddingFactory>>,
) -> Session {
    crate::runtime::new_server_session(conn, on_new_stream, padding).await
}
