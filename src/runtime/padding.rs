use crate::core::PaddingFactory;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;

pub struct DefaultPaddingFactory;

static DEFAULT_PADDING_FACTORY: OnceLock<Arc<RwLock<PaddingFactory>>> = OnceLock::new();

impl DefaultPaddingFactory {
    pub fn load() -> Arc<RwLock<PaddingFactory>> {
        DEFAULT_PADDING_FACTORY
            .get_or_init(|| Arc::new(RwLock::new(PaddingFactory::default())))
            .clone()
    }

    pub async fn update(raw_scheme: &[u8]) -> bool {
        if let Some(factory) = PaddingFactory::new(raw_scheme) {
            *Self::load().write().await = factory;
            true
        } else {
            false
        }
    }
}
