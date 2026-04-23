use crate::core::padding::PaddingFactory;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) struct AnyTlsState {
    padding: Arc<RwLock<PaddingFactory>>,
    peer_version: Arc<Mutex<u8>>,
    received_settings_from_client: Arc<Mutex<bool>>,
}

impl AnyTlsState {
    pub(crate) fn new(padding: Arc<RwLock<PaddingFactory>>) -> Arc<Self> {
        Arc::new(Self {
            padding,
            peer_version: Arc::new(Mutex::new(0)),
            received_settings_from_client: Arc::new(Mutex::new(false)),
        })
    }

    pub(crate) async fn padding(&self) -> PaddingFactory {
        self.padding.read().await.clone()
    }

    pub(crate) async fn set_padding(&self, padding: PaddingFactory) {
        *self.padding.write().await = padding;
    }

    pub(crate) fn peer_version(&self) -> u8 {
        *self.peer_version.lock()
    }

    pub(crate) fn set_peer_version(&self, version: u8) {
        *self.peer_version.lock() = version;
    }

    pub(crate) fn peer_version_handle(&self) -> Arc<Mutex<u8>> {
        self.peer_version.clone()
    }

    pub(crate) fn received_settings_from_client(&self) -> bool {
        *self.received_settings_from_client.lock()
    }

    pub(crate) fn mark_received_settings_from_client(&self) {
        *self.received_settings_from_client.lock() = true;
    }
}
