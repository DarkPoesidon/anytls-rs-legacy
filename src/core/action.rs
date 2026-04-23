use crate::core::Frame;
use bytes::Bytes;
use std::time::Duration;

pub(crate) enum ProtocolAction {
    SendFrame(Frame),
    SendFrameSync(Frame),
    PushStreamData { sid: u32, data: Bytes },
    EnsureIncomingStream { sid: u32 },
    CloseLocalStream { sid: u32 },
    CloseRemoteStream { sid: u32, message: String },
    CancelSynAckTimeout { sid: u32 },
    ArmSynAckTimeout { sid: u32, timeout: Duration },
    ReleaseWriteBuffering,
    AlertAndFail { message: String },
}
