use anytls::uot::{
    UotMode, UotRequest, uot_encode_packet, uot_get_packet_from_stream, uot_get_request_from_stream, uot_is_sentinel_destination,
    uot_sentinel_destination,
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
    let request = UotRequest::new(UotMode::Connected, Address::DomainAddress("dns.example".into(), 53));

    let bytes: Vec<u8> = request.clone().into();
    let mut reader = VecAsyncReader::new(bytes);
    let decoded = uot_get_request_from_stream(&mut reader).await.expect("request should decode");

    assert_eq!(decoded.mode, UotMode::Connected);
    assert_eq!(decoded.destination.to_string(), request.destination.to_string());
}

#[tokio::test]
async fn non_connect_packet_round_trip_preserves_destination_and_payload() {
    let destination = Address::DomainAddress("example.com".into(), 443);
    let payload = b"uot-payload";

    let bytes = uot_encode_packet(UotMode::Datagram, Some(&destination), payload).expect("frame should encode");
    let mut reader = VecAsyncReader::new(bytes);
    let (decoded_destination, decoded_payload) = uot_get_packet_from_stream(UotMode::Datagram, &mut reader)
        .await
        .expect("frame should decode");

    assert_eq!(decoded_destination.unwrap().to_string(), destination.to_string());
    assert_eq!(decoded_payload, payload);
}

#[tokio::test]
async fn connected_packet_round_trip_preserves_payload() {
    let payload = b"uot-connected-payload";

    let bytes = uot_encode_packet(UotMode::Connected, None, payload).expect("connected frame should encode");
    let mut reader = VecAsyncReader::new(bytes);
    let (_, decoded_payload) = uot_get_packet_from_stream(UotMode::Connected, &mut reader)
        .await
        .expect("connected frame should decode");

    assert_eq!(decoded_payload, payload);
}

#[test]
fn connected_packet_rejects_destination_argument() {
    let destination = Address::DomainAddress("example.com".into(), 443);
    let error = uot_encode_packet(UotMode::Connected, Some(&destination), b"payload")
        .expect_err("connected-mode packets must reject per-packet destinations");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn magic_destination_matches_server_uot_route_predicate() {
    assert!(uot_is_sentinel_destination(&uot_sentinel_destination()));
    assert!(!uot_is_sentinel_destination(&Address::DomainAddress("example.com".into(), 443)));
}

#[test]
fn connected_mode_requests_are_distinguishable_from_datagram_mode() {
    let request = UotRequest::new(UotMode::Connected, Address::DomainAddress("dns.example".into(), 53));

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
