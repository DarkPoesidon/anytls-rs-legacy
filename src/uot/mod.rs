//! UDP-over-TCP protocol implementation for AnyTLS.
//! This module defines the request format and packet encoding/decoding for the UDP-over-TCP protocol used in AnyTLS.
//! The protocol allows clients to send UDP packets encapsulated in TCP streams, enabling UDP communication over TCP connections.
//! The main components of this module include:
//! - `Request`: Represents a UDP-over-TCP request, containing the destination address and whether it's a connect request.
//! - `encode_request` and `read_request`: Functions to serialize and deserialize `Request` objects to and from byte streams.
//! - `encode_non_connect_packet` and `read_non_connect_packet`: Functions to handle non-connect UDP packets,
//!   including encoding the destination address and payload, and reading them from a stream.
//! - `encode_connected_packet` and `read_connected_packet`: Functions to handle connected-mode UDP packets,
//!   where the request destination is fixed for the whole stream and frames carry only payload length and bytes.
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UotMode {
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

pub fn request_destination() -> Address {
    Address::DomainAddress(V2_MAGIC_ADDRESS.into(), 0)
}

pub fn is_request_destination(address: &Address) -> bool {
    matches!(address, Address::DomainAddress(domain, _) if &**domain == V2_MAGIC_ADDRESS)
}

pub fn encode_request(request: &UotRequest) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(1 + request.destination.len());
    buf.put_u8(request.mode.into());
    request.destination.write_to_buf(&mut buf);
    buf.to_vec()
}

pub async fn read_request<R>(reader: &mut R) -> std::io::Result<UotRequest>
where
    R: AsyncRead + Unpin + Send + ?Sized,
{
    let mode = UotMode::try_from(reader.read_u8().await?)?;
    let destination = Address::retrieve_from_async_stream(reader).await?;

    Ok(UotRequest { mode, destination })
}

pub fn encode_datagram_packet(destination: &Address, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "UOT packet too large"));
    }

    let mut buf = BytesMut::with_capacity(destination.len() + 2 + payload.len());
    destination.write_to_buf(&mut buf);
    buf.put_u16(payload.len() as u16);
    buf.extend_from_slice(payload);
    Ok(buf.to_vec())
}

pub fn encode_connected_packet(payload: &[u8]) -> std::io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "UOT packet too large"));
    }

    let mut buf = BytesMut::with_capacity(2 + payload.len());
    buf.put_u16(payload.len() as u16);
    buf.extend_from_slice(payload);
    Ok(buf.to_vec())
}

pub async fn read_datagram_packet<R>(reader: &mut R) -> std::io::Result<(Address, Vec<u8>)>
where
    R: AsyncRead + Unpin + Send + ?Sized,
{
    let destination = Address::retrieve_from_async_stream(reader).await?;
    let payload_len = reader.read_u16().await? as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    Ok((destination, payload))
}

pub async fn read_connected_packet<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin + Send + ?Sized,
{
    let payload_len = reader.read_u16().await? as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    Ok(payload)
}
