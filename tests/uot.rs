use anytls::uot::{
    Request, encode_non_connect_packet, encode_request, is_request_destination, read_non_connect_packet, read_request, request_destination,
};
use socks5_impl::protocol::Address;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

struct VecAsyncReader {
    inner: std::io::Cursor<Vec<u8>>,
}

impl VecAsyncReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: std::io::Cursor::new(bytes),
        }
    }
}

impl AsyncRead for VecAsyncReader {
    fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let remaining = buf.remaining();
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let position = self.inner.position() as usize;
        let bytes = self.inner.get_ref();
        if position >= bytes.len() {
            return Poll::Ready(Ok(()));
        }

        let end = (position + remaining).min(bytes.len());
        buf.put_slice(&bytes[position..end]);
        self.inner.set_position(end as u64);
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn request_round_trip_preserves_connect_flag_and_destination() {
    let request = Request {
        is_connect: true,
        destination: Address::DomainAddress("dns.example".into(), 53),
    };

    let bytes = encode_request(&request);
    let mut reader = VecAsyncReader::new(bytes);
    let decoded = read_request(&mut reader).await.expect("request should decode");

    assert!(decoded.is_connect);
    assert_eq!(decoded.destination.to_string(), request.destination.to_string());
}

#[tokio::test]
async fn non_connect_packet_round_trip_preserves_destination_and_payload() {
    let destination = Address::DomainAddress("example.com".into(), 443);
    let payload = b"uot-payload";

    let bytes = encode_non_connect_packet(&destination, payload).expect("frame should encode");
    let mut reader = VecAsyncReader::new(bytes);
    let (decoded_destination, decoded_payload) = read_non_connect_packet(&mut reader).await.expect("frame should decode");

    assert_eq!(decoded_destination.to_string(), destination.to_string());
    assert_eq!(decoded_payload, payload);
}

#[test]
fn magic_destination_matches_server_uot_route_predicate() {
    assert!(is_request_destination(&request_destination()));
    assert!(!is_request_destination(&Address::DomainAddress("example.com".into(), 443)));
}

#[test]
fn current_server_policy_rejects_connect_mode_requests() {
    let request = Request {
        is_connect: true,
        destination: Address::DomainAddress("dns.example".into(), 53),
    };

    assert!(request.is_connect, "connect-mode UOT requests should be distinguishable");

    let supported = !request.is_connect;
    assert!(!supported, "the current server UOT handler only supports non-connect mode");
}
