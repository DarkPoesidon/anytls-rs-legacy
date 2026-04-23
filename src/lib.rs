pub mod core;
pub mod proxy;
pub mod util;

pub mod runtime;
pub mod runtime_padding;

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

pub type DialOutFunc = Box<dyn Fn() -> BoxFuture<'static, std::io::Result<Box<dyn AsyncReadWrite>>> + Send + Sync>;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub const PROGRAM_VERSION_NAME: &str = concat!(clap::crate_name!(), "/", clap::crate_version!());
