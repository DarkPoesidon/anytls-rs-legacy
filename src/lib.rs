#[cfg_attr(feature = "core", doc = "Core module")]
pub mod core;

#[cfg(feature = "runtime")]
pub mod proxy;
#[cfg(feature = "runtime")]
pub mod runtime;
#[cfg(any(feature = "client", feature = "server"))]
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

#[cfg(feature = "server")]
pub mod util;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub const PROGRAM_VERSION_NAME: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
