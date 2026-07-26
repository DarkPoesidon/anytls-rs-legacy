#[cfg(feature = "server")]
pub mod mkcert;

#[cfg(any(feature = "client", feature = "server"))]
pub mod parse_url;

#[cfg(feature = "server")]
mod retrieve_public_ip;
#[cfg(feature = "server")]
pub use retrieve_public_ip::retrieve_public_ip;
