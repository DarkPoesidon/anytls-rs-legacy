use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

pub type DialOutFunc = Box<dyn Fn() -> Box<dyn Future<Output = std::io::Result<Box<dyn AsyncReadWrite>>> + Send + Unpin> + Send + Sync>;
