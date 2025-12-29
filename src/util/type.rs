use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

pub type DialOutFunc = Box<dyn Fn() -> BoxFuture<'static, std::io::Result<Box<dyn AsyncReadWrite>>> + Send + Sync>;
