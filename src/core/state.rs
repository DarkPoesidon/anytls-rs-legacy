use crate::core::padding::PaddingFactory;
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;

pub struct State {
    padding: Arc<RwLock<PaddingFactory>>,
    peer_version: Arc<Mutex<u8>>,
    received_settings_from_client: Arc<Mutex<bool>>,
}

impl State {
    pub fn new(padding: PaddingFactory) -> Arc<Self> {
        Arc::new(Self {
            padding: Arc::new(RwLock::new(padding)),
            peer_version: Arc::new(Mutex::new(0)),
            received_settings_from_client: Arc::new(Mutex::new(false)),
        })
    }

    pub fn padding(&self) -> PaddingFactory {
        self.padding.read().clone()
    }

    pub fn set_padding(&self, padding: PaddingFactory) {
        *self.padding.write() = padding;
    }

    pub fn peer_version(&self) -> u8 {
        *self.peer_version.lock()
    }

    pub fn set_peer_version(&self, version: u8) {
        *self.peer_version.lock() = version;
    }

    #[cfg(feature = "runtime")]
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
