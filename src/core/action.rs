use crate::core::Frame;
use bytes::Bytes;

#[derive(Debug, Clone)]
pub enum ProtocolAction {
    SendFrame(Frame),
    SendFrameSync(Frame),
    PushStreamData { sid: u32, data: Bytes },
    EnsureIncomingStream { sid: u32 },
    CloseLocalStream { sid: u32 },
    CloseRemoteStream { sid: u32, message: String },
    ReleaseWriteBuffering,
    AlertAndFail { message: String },
}
