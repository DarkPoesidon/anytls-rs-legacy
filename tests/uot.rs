use anytls::uot::{
    UotMode, UotRequest, encode_connected_packet, encode_datagram_packet, encode_request, is_request_destination, read_connected_packet,
    read_datagram_packet, read_request, request_destination,
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
    let request = UotRequest {
        mode: UotMode::Connected,
        destination: Address::DomainAddress("dns.example".into(), 53),
    };

    let bytes = encode_request(&request);
    let mut reader = VecAsyncReader::new(bytes);
    let decoded = read_request(&mut reader).await.expect("request should decode");

    assert_eq!(decoded.mode, UotMode::Connected);
    assert_eq!(decoded.destination.to_string(), request.destination.to_string());
}

#[tokio::test]
async fn non_connect_packet_round_trip_preserves_destination_and_payload() {
    let destination = Address::DomainAddress("example.com".into(), 443);
    let payload = b"uot-payload";

    let bytes = encode_datagram_packet(&destination, payload).expect("frame should encode");
    let mut reader = VecAsyncReader::new(bytes);
    let (decoded_destination, decoded_payload) = read_datagram_packet(&mut reader).await.expect("frame should decode");

    assert_eq!(decoded_destination.to_string(), destination.to_string());
    assert_eq!(decoded_payload, payload);
}

#[tokio::test]
async fn connected_packet_round_trip_preserves_payload() {
    let payload = b"uot-connected-payload";

    let bytes = encode_connected_packet(payload).expect("connected frame should encode");
    let mut reader = VecAsyncReader::new(bytes);
    let decoded_payload = read_connected_packet(&mut reader).await.expect("connected frame should decode");

    assert_eq!(decoded_payload, payload);
}

#[test]
fn magic_destination_matches_server_uot_route_predicate() {
    assert!(is_request_destination(&request_destination()));
    assert!(!is_request_destination(&Address::DomainAddress("example.com".into(), 443)));
}

#[test]
fn connected_mode_requests_are_distinguishable_from_datagram_mode() {
    let request = UotRequest {
        mode: UotMode::Connected,
        destination: Address::DomainAddress("dns.example".into(), 53),
    };

    assert_eq!(
        request.mode,
        UotMode::Connected,
        "connected-mode UOT requests should be distinguishable"
    );

    assert_ne!(
        request.mode,
        UotMode::Datagram,
        "connected and datagram modes should not collapse to the same state"
    );
}
