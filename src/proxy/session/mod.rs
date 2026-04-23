pub mod client;
pub mod inner;
pub mod stream;

use crate::AsyncReadWrite;
use crate::core::PaddingFactory;
use std::sync::Arc;
use tokio::sync::RwLock;

pub use client::Client;
pub use inner::Session;
pub use stream::Stream;

pub async fn new_client_session(conn: Box<dyn AsyncReadWrite>, padding: Arc<RwLock<PaddingFactory>>) -> Session {
    crate::runtime::new_client_session(conn, padding).await
}

pub async fn new_server_session(
    conn: Box<dyn AsyncReadWrite>,
    on_new_stream: Box<dyn Fn(Arc<Stream>) + Send + Sync>,
    padding: Arc<RwLock<PaddingFactory>>,
) -> Session {
    crate::runtime::new_server_session(conn, on_new_stream, padding).await
}
