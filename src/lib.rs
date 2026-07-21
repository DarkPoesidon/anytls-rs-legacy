#[cfg_attr(feature = "core", doc = "Core module")]
pub mod core;

#[cfg(feature = "runtime")]
pub mod proxy;
#[cfg(feature = "runtime")]
pub mod runtime;
#[cfg(feature = "uot")]
pub mod uot;
#[cfg(feature = "runtime")]
use futures::future::BoxFuture;
#[cfg(feature = "runtime")]
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "runtime")]
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
#[cfg(feature = "runtime")]
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
#[cfg(feature = "runtime")]
pub type DialOutFunc = Box<dyn Fn() -> BoxFuture<'static, std::io::Result<Box<dyn AsyncReadWrite>>> + Send + Sync>;

#[cfg(any(feature = "server", feature = "client"))]
mod util;

#[cfg(any(feature = "server", feature = "client"))]
pub use util::*;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub const PROGRAM_VERSION_NAME: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

// Protocol version number (exported). Increment when making incompatible
// protocol changes that affect the "v" settings field used during session
// negotiation.
pub const PROTOCOL_VERSION: u8 = 2;
// Minimum protocol version we remain compatible with (legacy clients).
pub const MIN_PROTOCOL_VERSION: u8 = 2;
