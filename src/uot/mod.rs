//! UDP-over-TCP protocol implementation for AnyTLS.
//! This module defines the request format and packet encoding/decoding for the UDP-over-TCP protocol used in AnyTLS.
//! The protocol allows clients to send UDP packets encapsulated in TCP streams, enabling UDP communication over TCP connections.
//! The main components of this module include:
//! - `Request`: Represents a UDP-over-TCP request, containing the destination address and whether it's a connect request.
//! - `encode_request` and `read_request`: Functions to serialize and deserialize `Request` objects to and from byte streams.
//! - `encode_non_connect_packet` and `read_non_connect_packet`: Functions to handle non-connect UDP packets,
//!   including encoding the destination address and payload, and reading them from a stream.
//!
//! The module also defines a special magic address used to identify UDP-over-TCP requests and provides utility functions to work with this protocol.
//!
//! Protocol details:
//! - The outer AnyTLS stream destination is the sentinel address `sp.v2.udp-over-tcp.arpa`.
//!   When the server reads this destination from a newly created stream, it switches from the normal
//!   TCP relay path to the UOT handler.
//! - Immediately after that outer destination, the client sends a UOT request encoded as:
//!   `[u8 is_connect][SOCKS address destination]`.
//! - `is_connect = 0` means non-connect mode. In this mode, each UDP packet carried inside the stream
//!   contains its own destination address.
//! - `is_connect = 1` means connect mode. In this mode, the request destination becomes the fixed UDP
//!   peer for the whole stream, and subsequent payload frames no longer need to carry a destination.
//! - Non-connect packet format is `[SOCKS address destination][u16be payload_len][payload]`.
//! - Connect packet format is `[u16be payload_len][payload]`.
//! - The current Rust implementation only supports non-connect mode. If a peer sends `is_connect = 1`,
//!   the server rejects that stream.
//!

use bytes::{BufMut, BytesMut};
use socks5_impl::protocol::{Address, AsyncStreamOperation, StreamOperation};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const V2_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

#[derive(Clone, Debug)]
pub struct Request {
    pub is_connect: bool,
    pub destination: Address,
}

pub fn request_destination() -> Address {
    Address::DomainAddress(V2_MAGIC_ADDRESS.into(), 0)
}

pub fn is_request_destination(address: &Address) -> bool {
    matches!(address, Address::DomainAddress(domain, _) if &**domain == V2_MAGIC_ADDRESS)
}

pub fn encode_request(request: &Request) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(1 + request.destination.len());
    buf.put_u8(u8::from(request.is_connect));
    request.destination.write_to_buf(&mut buf);
    buf.to_vec()
}

pub async fn read_request<R>(reader: &mut R) -> std::io::Result<Request>
where
    R: AsyncRead + Unpin + Send + ?Sized,
{
    let is_connect = reader.read_u8().await? != 0;
    let destination = Address::retrieve_from_async_stream(reader).await?;

    Ok(Request { is_connect, destination })
}

pub fn encode_non_connect_packet(destination: &Address, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "UOT packet too large"));
    }

    let mut buf = BytesMut::with_capacity(destination.len() + 2 + payload.len());
    destination.write_to_buf(&mut buf);
    buf.put_u16(payload.len() as u16);
    buf.extend_from_slice(payload);
    Ok(buf.to_vec())
}

pub async fn read_non_connect_packet<R>(reader: &mut R) -> std::io::Result<(Address, Vec<u8>)>
where
    R: AsyncRead + Unpin + Send + ?Sized,
{
    let destination = Address::retrieve_from_async_stream(reader).await?;
    let payload_len = reader.read_u16().await? as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    Ok((destination, payload))
}
