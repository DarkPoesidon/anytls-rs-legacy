//! UDP-over-TCP protocol implementation for AnyTLS.
//! This module defines the request format and packet encoding/decoding for the UDP-over-TCP protocol used in AnyTLS.
//! The protocol allows clients to send UDP packets encapsulated in TCP streams, enabling UDP communication over TCP connections.
//! The main components of this module include:
//! - `UotRequest`: Represents a UDP-over-TCP request, containing the transfer mode and request destination.
//! - `From<UotRequest> for Vec<u8>` and `uot_get_request_from_stream`: Helpers to serialize and deserialize
//!   `UotRequest` values to and from byte streams.
//! - `uot_sentinel_destination` and `uot_is_sentinel_destination`: Helpers to work with the outer AnyTLS
//!   sentinel destination used to switch a stream into UOT mode.
//! - `uot_encode_packet` and `uot_get_packet_from_stream`: Helpers to encode and decode UOT payload frames for
//!   both datagram mode and connected mode.
//!
//! The module also defines a special magic address used to identify UDP-over-TCP requests and provides utility functions to work with this protocol.
//!
//! Protocol details:
//! - The outer AnyTLS stream destination is the sentinel address `sp.v2.udp-over-tcp.arpa`.
//!   When the server reads this destination from a newly created stream, it switches from the normal
//!   TCP relay path to the UOT handler.
//! - Immediately after that outer destination, the client sends a UOT request encoded as:
//!   `[u8 mode][SOCKS address destination]`.
//! - `mode = 0` means datagram mode. In this mode, each UDP packet carried inside the stream
//!   contains its own destination address.
//! - `mode = 1` means connected mode. In this mode, the request destination becomes the fixed UDP
//!   peer for the whole stream, and subsequent payload frames no longer need to carry a destination.
//! - Non-connect packet format is `[SOCKS address destination][u16be payload_len][payload]`.
//! - Connect packet format is `[u16be payload_len][payload]`.
//! - The current Rust implementation supports both datagram mode and connected mode in the server-side
//!   UOT handler. The bundled SOCKS5 client-side UDP ASSOCIATE path still emits datagram mode requests.
//!

use bytes::{BufMut, BytesMut};
use socks5_impl::protocol::{Address, AsyncStreamOperation, StreamOperation};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const V2_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum UotMode {
    #[default]
    Datagram = 0,
    Connected = 1,
}

impl TryFrom<u8> for UotMode {
    type Error = std::io::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use std::io::{Error, ErrorKind::InvalidData};
        match value {
            0 => Ok(UotMode::Datagram),
            1 => Ok(UotMode::Connected),
            other => Err(Error::new(InvalidData, format!("invalid UOT mode: {other}"))),
        }
    }
}

impl From<UotMode> for u8 {
    fn from(mode: UotMode) -> Self {
        mode as u8
    }
}

#[derive(Clone, Debug)]
pub struct UotRequest {
    pub mode: UotMode,
    pub destination: Address,
}

impl From<UotRequest> for Vec<u8> {
    fn from(request: UotRequest) -> Self {
        let mut buf = BytesMut::with_capacity(1 + request.destination.len());
        buf.put_u8(request.mode.into());
        request.destination.write_to_buf(&mut buf);
        buf.to_vec()
    }
}

impl UotRequest {
    pub fn new(mode: UotMode, destination: Address) -> Self {
        Self { mode, destination }
    }
}

pub fn uot_sentinel_destination() -> Address {
    Address::DomainAddress(V2_MAGIC_ADDRESS.into(), 0)
}

pub fn uot_is_sentinel_destination(address: &Address) -> bool {
    matches!(address, Address::DomainAddress(domain, _) if &**domain == V2_MAGIC_ADDRESS)
}

pub async fn uot_get_request_from_stream<R>(reader: &mut R) -> std::io::Result<UotRequest>
where
    R: AsyncRead + Unpin + Send + ?Sized,
{
    let mode = UotMode::try_from(reader.read_u8().await?)?;
    let destination = Address::retrieve_from_async_stream(reader).await?;

    Ok(UotRequest::new(mode, destination))
}

/// Encodes a UDP-over-TCP packet with the given mode, destination, and payload.
/// For datagram mode, the destination is required and included in the packet.
/// For connected mode, the destination must be omitted because it is fixed for the stream.
/// The packet format is:
/// - Datagram mode: `[SOCKS address destination][u16be payload_len][payload]`
/// - Connected mode: `[u16be payload_len][payload]`
pub fn uot_encode_packet(mode: UotMode, destination: Option<&Address>, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind::InvalidInput};
    if payload.len() > u16::MAX as usize {
        return Err(Error::new(InvalidInput, "UOT packet too large"));
    }

    match mode {
        UotMode::Datagram => {
            let destination = destination.ok_or_else(|| Error::new(InvalidInput, "Datagram mode requires a destination"))?;
            let mut buf = BytesMut::with_capacity(destination.len() + 2 + payload.len());
            destination.write_to_buf(&mut buf);
            buf.put_u16(payload.len() as u16);
            buf.extend_from_slice(payload);
            Ok(buf.to_vec())
        }
        UotMode::Connected => {
            if destination.is_some() {
                return Err(Error::new(InvalidInput, "Connected mode does not allow a destination"));
            }

            let mut buf = BytesMut::with_capacity(2 + payload.len());
            buf.put_u16(payload.len() as u16);
            buf.extend_from_slice(payload);
            Ok(buf.to_vec())
        }
    }
}

/// Reads a UDP-over-TCP packet from the given stream according to the specified mode.
/// For datagram mode, it reads the destination address and payload from the stream.
/// For connected mode, it reads only the payload since the destination is fixed for the stream.
/// The expected packet format from the stream is:
/// - Datagram mode: `[SOCKS address destination][u16be payload_len][payload]`
/// - Connected mode: `[u16be payload_len][payload]`
pub async fn uot_get_packet_from_stream<R>(mode: UotMode, reader: &mut R) -> std::io::Result<(Option<Address>, Vec<u8>)>
where
    R: AsyncRead + Unpin + Send + ?Sized,
{
    match mode {
        UotMode::Datagram => {
            let destination = Address::retrieve_from_async_stream(reader).await?;
            let payload_len = reader.read_u16().await? as usize;
            let mut payload = vec![0u8; payload_len];
            reader.read_exact(&mut payload).await?;
            Ok((Some(destination), payload))
        }
        UotMode::Connected => {
            let payload_len = reader.read_u16().await? as usize;
            let mut payload = vec![0u8; payload_len];
            reader.read_exact(&mut payload).await?;
            Ok((None, payload))
        }
    }
}
