pub mod proxy;
pub mod util;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub use util::version::PROGRAM_VERSION_NAME;
