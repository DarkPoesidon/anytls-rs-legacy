pub mod proxy;
pub mod util;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub const PROGRAM_VERSION_NAME: &str = concat!(clap::crate_name!(), "/", clap::crate_version!());
