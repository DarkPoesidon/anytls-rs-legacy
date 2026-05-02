use anytls::core::{Command, Frame, PaddingFactory};
use anytls::proxy::session::DEFAULT_SID;
use anytls::proxy::session::new_server_session;
use anytls::runtime::DefaultPaddingFactory;
use anytls::uot::{
    UotMode, UotRequest, uot_encode_packet, uot_get_packet_from_stream, uot_get_request_from_stream, uot_is_sentinel_destination,
};
use anytls::{BoxError, PROGRAM_VERSION_NAME, util::mkcert};
use clap::Parser;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
#[command(version, author, name = "anytls-server", about = "AnyTLS Server")]
struct Args {
    #[arg(short = 'l', long, default_value = "0.0.0.0:8443", help = "Server listen port")]
    listen: SocketAddr,

    #[arg(short = 'p', long, help = "Password")]
    password: String,

    #[arg(long, help = "Padding scheme file")]
    padding_scheme: Option<PathBuf>,

    #[arg(long, help = "TLS server name indication (SNI)")]
    sni: Option<String>,

    #[arg(long, help = "TLS certificate PEM file (optional)")]
    cert: Option<PathBuf>,

    #[arg(long, help = "TLS private key PEM file (optional)")]
    key: Option<PathBuf>,

    #[arg(long, default_value = "info", help = "Log level (off, error, warn, info, debug, trace)")]
    log: log::LevelFilter,
}

struct StreamReader {
    inner: Arc<anytls::proxy::session::Session>,
    #[allow(clippy::type_complexity)]
    read_fut: Option<std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<(Vec<u8>, usize)>> + Send>>>,
}

impl tokio::io::AsyncRead for StreamReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if let Some(fut) = self.read_fut.as_mut() {
                match fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(Ok((v, n))) => {
                        self.read_fut = None;
                        buf.put_slice(&v[..n]);
                        return std::task::Poll::Ready(Ok(()));
                    }
                    std::task::Poll::Ready(Err(e)) => {
                        self.read_fut = None;
                        return std::task::Poll::Ready(Err(e));
                    }
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }

            let remaining = buf.remaining();
            if remaining == 0 {
                return std::task::Poll::Ready(Ok(()));
            }

            let inner = self.inner.clone();
            self.read_fut = Some(Box::pin(async move {
                let mut v = vec![0_u8; remaining];
                let n = inner.read(&mut v).await?;
                Ok::<(Vec<u8>, usize), std::io::Error>((v, n))
            }));
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    let ctrlc_future = ctrlc2::AsyncCtrlC::new(move || {
        log::trace!("Ctrl+C received, cancelling...");
        cancel_token_clone.cancel();
        true
    })?;

    let main_worker = tokio::spawn(run(cancel_token));

    ctrlc_future.await?;
    if let Err(e) = main_worker.await? {
        log::warn!("Main worker error: {}", e);
    }

    Ok(())
}

async fn run(cancel_token: tokio_util::sync::CancellationToken) -> Result<(), BoxError> {
    let args = Args::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(args.log.to_string())).init();

    if args.password.is_empty() {
        log::error!("Please set password");
        std::process::exit(1);
    }

    let password_sha256 = Sha256::digest(args.password.as_bytes());

    // Load padding scheme if provided
    if let Some(padding_file) = args.padding_scheme {
        let content = tokio::fs::read(&padding_file).await?;
        if DefaultPaddingFactory::update(&content).await {
            log::info!("Loaded padding scheme file: {}", padding_file.display());
        } else {
            log::error!("Wrong format padding scheme file: {}", padding_file.display());
            std::process::exit(1);
        }
    }

    log::info!("[Server] {}", PROGRAM_VERSION_NAME);
    log::info!("[Server] Listening TCP {}", args.listen);

    let listener = TcpListener::bind(&args.listen).await?;

    let tls_config = create_tls_config(args.sni.as_deref(), args.cert.as_deref(), args.key.as_deref())?;
    let acceptor = TlsAcceptor::from(tls_config);
    let padding = DefaultPaddingFactory::load();
    let connection_id = Arc::new(AtomicU64::new(0));

    loop {
        let (stream, addr) = tokio::select! {
            _ = cancel_token.cancelled() => {
                log::info!("Shutting down server...");
                break Ok(());
            }
            res = listener.accept() => res?,
        };

        log::debug!("Accepted connection from: {}", addr);
        let conn_id = connection_id.fetch_add(1, Ordering::Relaxed);

        let _ = stream.set_nodelay(true);
        let sock_ref = socket2::SockRef::from(&stream);
        let mut ka = socket2::TcpKeepalive::new();
        ka = ka.with_time(std::time::Duration::from_secs(60));
        ka = ka.with_interval(std::time::Duration::from_secs(10));
        let _ = sock_ref.set_tcp_keepalive(&ka);

        let acceptor = acceptor.clone();
        let padding = padding.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(conn_id, stream, acceptor, password_sha256.to_vec(), padding).await {
                log::debug!("Connection #{conn_id} error: {e}");
            }
        });
    }
}

fn create_tls_config(sni: Option<&str>, cert_path: Option<&Path>, key_path: Option<&Path>) -> Result<Arc<ServerConfig>, BoxError> {
    // If both cert and key paths provided, load them from PEM files
    if let (Some(cert_p), Some(key_p)) = (cert_path, key_path) {
        let cert_file = std::fs::File::open(cert_p)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let certs_iter = rustls_pemfile::certs(&mut cert_reader);
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> = certs_iter.collect::<Result<_, _>>()?;

        let key_file = std::fs::File::open(key_p)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        // Try pkcs8 first
        let keys_pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut key_reader).collect::<Result<Vec<_>, _>>()?;

        let key_der = if !keys_pkcs8.is_empty() {
            rustls::pki_types::PrivateKeyDer::Pkcs8(keys_pkcs8.into_iter().next().unwrap())
        } else {
            // Rewind and try rsa
            let key_file = std::fs::File::open(key_p)?;
            let mut key_reader = std::io::BufReader::new(key_file);
            let keys_rsa = rustls_pemfile::rsa_private_keys(&mut key_reader).collect::<Result<Vec<_>, _>>()?;
            if keys_rsa.is_empty() {
                return Err("failed to parse private key as PKCS#8 or RSA".into());
            }
            rustls::pki_types::PrivateKeyDer::Pkcs1(keys_rsa.into_iter().next().unwrap())
        };

        if certs.is_empty() {
            return Err("failed to parse cert PEM".into());
        }

        let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = certs.into_iter().collect();
        let key = key_der;

        let config = ServerConfig::builder().with_no_client_auth().with_single_cert(cert_chain, key)?;

        return Ok(Arc::new(config));
    }

    // Fallback: generate ephemeral cert (existing behavior)
    let cert = mkcert::generate_key_pair(sni.unwrap_or(""))?;
    Ok(Arc::new(cert))
}

async fn handle_connection(
    conn_id: u64,
    stream: TcpStream,
    acceptor: TlsAcceptor,
    password_sha256: Vec<u8>,
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
) -> Result<(), BoxError> {
    let mut tls_stream = acceptor.accept(stream).await?;

    // Read authentication
    let mut auth_data = vec![0u8; 34]; // 32 bytes password + 2 bytes padding length
    tls_stream.read_exact(&mut auth_data).await?;

    let received_password = &auth_data[..32];
    let addr = tls_stream.get_ref().0.peer_addr()?;
    if received_password != password_sha256.as_slice() {
        log::debug!("Connection #{conn_id}: authentication failed for {addr}",);
        return Ok(());
    }
    log::debug!("Connection #{conn_id}: authentication successful for {addr}");

    let padding_len = u16::from_be_bytes([auth_data[32], auth_data[33]]);
    if padding_len > 0 {
        let mut padding_data = vec![0u8; padding_len as usize];
        tls_stream.read_exact(&mut padding_data).await?;
    }

    // Create session
    let session = new_server_session(
        Box::new(tls_stream),
        Box::new(move |session| {
            // Handle new session (logical stream)
            tokio::spawn(async move {
                if let Err(e) = handle_session(conn_id, session).await {
                    log::debug!("Session error: {}", e);
                }
            });
        }),
        padding,
    )
    .await;

    log::debug!("Connection #{conn_id}: session created, entering run loop");
    session.run().await?;
    log::debug!("Connection #{conn_id}: session run loop exited");
    Ok(())
}

async fn handle_session(conn_id: u64, session: Arc<anytls::proxy::session::Session>) -> Result<(), BoxError> {
    log::debug!("Handling new session");
    let mut reader = StreamReader {
        inner: session.clone(),
        read_fut: None,
    };
    use socks5_impl::protocol::{Address, AsyncStreamOperation};
    loop {
        if session.is_closed().await {
            return Ok(());
        }

        let destination = match Address::retrieve_from_async_stream(&mut reader).await {
            Ok(destination) => destination,
            Err(err) if session.is_closed().await || is_logical_stream_end(&err) => {
                log::debug!("Session handler exiting after stream end: {err}");
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };

        if uot_is_sentinel_destination(&destination) {
            log::debug!("Connection #{conn_id}: Received UOT sentinel destination, treating as UOT stream");
            handle_uot_stream(session.clone(), &mut reader).await?;
        } else {
            log::debug!("Connection #{conn_id}: Received TCP destination {destination}, treating as TCP stream");
            handle_tcp_stream(session.clone(), destination.to_string()).await?;
        }
    }
}

async fn handle_uot_stream(stream: Arc<anytls::proxy::session::Session>, reader: &mut StreamReader) -> Result<(), BoxError> {
    let request = uot_get_request_from_stream(reader).await?;
    match request.mode {
        UotMode::Connected => handle_uot_connected_stream(stream, reader, &request).await,
        UotMode::Datagram => handle_uot_datagram_stream(stream, reader).await,
    }
}

async fn handle_uot_datagram_stream(stream: Arc<anytls::proxy::session::Session>, reader: &mut StreamReader) -> Result<(), BoxError> {
    let mut outbound_buf = vec![0u8; 65_535];

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    stream.handshake_success().await?;

    let result: Result<(), BoxError> = async {
        loop {
            tokio::select! {
                res = uot_get_packet_from_stream(UotMode::Datagram, reader) => {
                    let (destination, payload) = match res {
                        Ok(packet) => packet,
                        Err(err) if is_logical_stream_end(&err) => break Ok(()),
                        Err(err) => break Err(err.into()),
                    };
                    udp_socket.send_to(&payload, destination.unwrap().to_string()).await?;
                }
                res = udp_socket.recv_from(&mut outbound_buf) => {
                    let (n, source) = res?;
                    let frame = uot_encode_packet(UotMode::Datagram, Some(&socks5_impl::protocol::Address::from(source)), &outbound_buf[..n])?;
                    stream.write(&frame).await?;
                }
            }
        }
    }
    .await;

    if let Err(err) = &result {
        log::warn!("UOT relay error: {err}");
    }

    result
}

async fn handle_uot_connected_stream(
    stream: Arc<anytls::proxy::session::Session>,
    reader: &mut StreamReader,
    request: &UotRequest,
) -> Result<(), BoxError> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;

    let fixed_destination = request.destination.to_string();
    if let Err(err) = udp_socket.connect(&fixed_destination).await {
        log::debug!("Failed to connect UDP socket to {fixed_destination}: {err}");
        stream.handshake_failure(&err.to_string()).await?;
        stream.terminate().await?;
        return Err(err.into());
    }

    stream.handshake_success().await?;

    let mut outbound_buf = vec![0u8; 65_535];

    let result: Result<(), BoxError> = async {
        loop {
            tokio::select! {
                res = uot_get_packet_from_stream(UotMode::Connected, reader) => {
                    let (_, payload) = match res {
                        Ok(packet) => packet,
                        Err(err) if is_logical_stream_end(&err) => break Ok(()),
                        Err(err) => break Err(err.into()),
                    };
                    udp_socket.send(&payload).await?;
                }
                res = udp_socket.recv(&mut outbound_buf) => {
                    let n = res?;
                    let frame = uot_encode_packet(UotMode::Connected, None, &outbound_buf[..n])?;
                    stream.write(&frame).await?;
                }
            }
        }
    }
    .await;

    if let Err(err) = &result {
        log::warn!("Connected UOT relay error: {err}");
    }

    result
}

async fn handle_tcp_stream(stream: Arc<anytls::proxy::session::Session>, destination: String) -> Result<(), BoxError> {
    log::debug!("Connecting to {}", destination);
    let mut outbound = match TcpStream::connect(&destination).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("Failed to connect to {destination}: {e}");
            stream.handshake_failure(&e.to_string()).await?;
            stream.terminate().await?;
            return Err(e.into());
        }
    };

    // Report success
    stream.handshake_success().await?;

    log::debug!("Starting relay to destination {destination}");
    // Relay data
    let stream_read = stream.clone();
    let stream_write = stream.clone();
    let (mut outbound_read, mut outbound_write) = outbound.split();
    let relay_cancel = tokio_util::sync::CancellationToken::new();

    // Use a custom copy loop for Stream -> Outbound because Stream doesn't implement AsyncRead in a way compatible with copy
    // Wait, Stream implements AsyncRead but it's a placeholder.
    // We need to use the read method directly or fix AsyncRead.
    // Since we have split_ref returning Self, and Self has read(), let's use a custom loop.

    let s2o = async {
        use tokio::io::AsyncWriteExt;
        let mut buf = vec![0u8; 4096];
        let mut cancelled = false;
        let res = loop {
            tokio::select! {
                _ = relay_cancel.cancelled() => {
                    cancelled = true;
                    break Ok(());
                },
                res = stream_read.read(&mut buf) => match res {
                    Ok(0) => {
                        break Ok(());
                    }
                    Ok(n) => {
                        if let Err(e) = outbound_write.write_all(&buf[..n]).await {
                            log::debug!("Relay s2o error writing to outbound {}: {e}", destination);
                            break Err(e);
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
        };
        if let Err(ref e) = res {
            log::warn!("Error relaying to outbound {}: {e}", destination);
        }
        if !cancelled {
            outbound_write.shutdown().await?;
        }
        if res.is_err() {
            relay_cancel.cancel();
        }
        log::debug!("s2o finished (client->outbound)");
        Ok::<(), std::io::Error>(())
    };

    let o2s = async {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 4096];
        let res = loop {
            tokio::select! {
                _ = relay_cancel.cancelled() => break Ok(()),
                res = outbound_read.read(&mut buf) => match res {
                    // Remote closed backend connection: send FIN to client and
                    // finish only the current logical stream so the session can
                    // handle the next target address.
                    Ok(0) => {
                        stream_write.write_frame(Frame::new(Command::Fin, DEFAULT_SID)).await?;
                        stream_write.mark_local_stream_closed(DEFAULT_SID).await?;
                        break Ok(());
                    }
                    Ok(n) => {
                        if let Err(e) = stream_write.write(&buf[..n]).await {
                            log::debug!("Relay o2s error writing to client for {}: {e}", destination);
                            break Err(e);
                        }
                    }
                    Err(e) => break Err(e),
                }
            }
        };
        if let Err(ref e) = res {
            log::warn!("Error relaying from outbound {}: {e}", destination);
        }
        if res.is_err() {
            relay_cancel.cancel();
        }
        log::debug!("o2s finished (outbound->client)");
        Ok::<(), std::io::Error>(())
    };

    match tokio::join!(s2o, o2s) {
        (Ok(_), Ok(_)) => log::debug!("Relay finished"),
        (Err(e), _) | (_, Err(e)) => log::warn!("Relay error: {e}"),
    }

    Ok(())
}

fn is_logical_stream_end(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe)
}
