use crate::core::{Frame, State};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;

#[async_trait]
pub trait ProtocolHost: Send + Sync {
    fn is_client(&self) -> bool;

    fn protocol_state(&self) -> Arc<State>;

    async fn send_frame(&self, frame: Frame) -> std::io::Result<usize>;

    async fn send_frame_sync(&self, frame: Frame) -> std::io::Result<usize>;

    async fn push_stream_data(&self, sid: u32, data: Bytes) -> std::io::Result<()>;

    async fn ensure_incoming_stream(&self, sid: u32) -> std::io::Result<()>;

    async fn close_local_stream(&self, sid: u32) -> std::io::Result<()>;

    async fn close_remote_stream(&self, sid: u32, message: String) -> std::io::Result<()>;

    async fn cancel_synack_timeout(&self, sid: u32);

    async fn arm_synack_timeout(&self, sid: u32, timeout: Duration);

    async fn release_write_buffering(&self);
}
