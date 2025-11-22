use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

pub const HEADER_OVERHEAD_SIZE: usize = 1 + 4 + 2;

#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: u8,
    pub sid: u32,
    pub data: Bytes,
}

impl Frame {
    pub fn new(cmd: u8, sid: u32) -> Self {
        Self {
            cmd,
            sid,
            data: Bytes::new(),
        }
    }

    pub fn with_data(cmd: u8, sid: u32, data: Bytes) -> Self {
        Self { cmd, sid, data }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + self.data.len());
        buf.put_u8(self.cmd);
        buf.put_u32(self.sid);
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(&self.data);
        buf.freeze()
    }

    pub fn from_bytes(mut data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_OVERHEAD_SIZE {
            return None;
        }

        let cmd = data.get_u8();
        let sid = data.get_u32();
        let length = data.get_u16() as usize;

        if data.len() < length {
            return None;
        }

        let frame_data = data[..length].to_vec();
        data.advance(length);

        Some(Self {
            cmd,
            sid,
            data: frame_data.into(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RawHeader {
    pub cmd: u8,
    pub sid: u32,
    pub length: u16,
}

impl RawHeader {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_OVERHEAD_SIZE {
            return None;
        }

        let mut buf = data;
        let cmd = buf.get_u8();
        let sid = buf.get_u32();
        let length = buf.get_u16();

        Some(Self { cmd, sid, length })
    }
}
