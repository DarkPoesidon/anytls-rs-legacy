use anytls::core::PaddingFactory;
use anytls::proxy::session::{Stream, new_server_session};
use anytls::runtime::DefaultPaddingFactory;
use anytls::uot::{
    UotMode, UotRequest, uot_encode_packet, uot_get_packet_from_stream, uot_get_request_from_stream, uot_is_sentinel_destination,
};
use anytls::{BoxError, PROGRAM_VERSION_NAME, mkcert};
use clap::Parser;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use socks5_impl::client::{self, SocksUdpClient, create_udp_client};
use socks5_impl::protocol::{Address, ProxyParameters, ProxyType};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::client::TlsConnector;
use uuid::Uuid;
use x509_parser::extensions::{GeneralName, ParsedExtension};

#[derive(Parser)]
#[command(version, author, name = "anytls-server", about = "AnyTLS Server")]
struct Args {
    #[arg(short = 'l', long, default_value = "0.0.0.0:443", help = "Server listen port")]
    listen: SocketAddr,

    #[arg(short = 'p', long, help = "Password")]
    password: String,

    #[arg(long, value_name = "FILE", help = "Padding scheme file")]
    padding_scheme: Option<PathBuf>,

    #[arg(long, help = "TLS server name indication (SNI)")]
    sni: Option<String>,

    #[arg(long, value_name = "FILE", help = "TLS certificate PEM file (optional)")]
    cert: Option<PathBuf>,

    #[arg(long, value_name = "FILE", help = "TLS private key PEM file (optional)")]
    key: Option<PathBuf>,

    /// Outbound SOCKS5 proxy url in the format socks5://[user[:password]@]host:port
    #[arg(long, value_name = "url")]
    outbound_proxy: Option<ProxyParameters>,

    #[arg(long, default_value = "info", help = "Log level (off, error, warn, info, debug, trace)")]
    log: log::LevelFilter,
}

struct StreamReader {
    inner: Arc<Stream>,
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
    tokio::pin!(ctrlc_future);

    let mut main_worker = tokio::spawn(run(cancel_token));

    tokio::select! {
        worker_result = &mut main_worker => {
            worker_result??;
        }
        ctrlc_result = &mut ctrlc_future => {
            ctrlc_result?;
            if let Err(error) = main_worker.await? {
                log::warn!("Main worker error: {error}");
            }
        }
    }

    Ok(())
}

async fn run(cancel_token: tokio_util::sync::CancellationToken) -> Result<(), BoxError> {
    let args = Args::parse();
    let outbound_proxy = args.outbound_proxy;
    if let Some(proxy) = &outbound_proxy
        && proxy.proxy_type != ProxyType::Socks5
    {
        return Err("Only SOCKS5 proxy is supported for outbound_socks5".into());
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(args.log.to_string())).init();

    if args.password.is_empty() {
        log::error!("Please set password");
        std::process::exit(1);
    }

    let p_hash = Sha256::digest(args.password.as_bytes());

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

    let (tls_config, probe_sni_allowlist) = create_tls_config(args.sni.as_deref(), args.cert.as_deref(), args.key.as_deref())?;
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(&args.listen).await?;
    let padding = DefaultPaddingFactory::load();

    log::info!("[Server] {}", PROGRAM_VERSION_NAME);
    log::info!("[Server] Listening TCP {}", args.listen);

    loop {
        let (stream, addr) = tokio::select! {
            _ = cancel_token.cancelled() => {
                log::info!("Shutting down server...");
                break Ok(());
            }
            res = listener.accept() => res?,
        };

        log::debug!("Accepted connection from: {}", addr);

        let _ = stream.set_nodelay(true);
        let sock_ref = socket2::SockRef::from(&stream);
        let mut ka = socket2::TcpKeepalive::new();
        ka = ka.with_time(std::time::Duration::from_secs(60));
        ka = ka.with_interval(std::time::Duration::from_secs(10));
        let _ = sock_ref.set_tcp_keepalive(&ka);

        let acceptor = acceptor.clone();
        let padding = padding.clone();
        let probe_sni_allowlist = probe_sni_allowlist.clone();

        let outbound_proxy = outbound_proxy.clone();
        tokio::spawn(async move {
            let addr = stream.peer_addr().ok();
            if let Err(e) = handle_connection(stream, acceptor, p_hash.to_vec(), padding, probe_sni_allowlist, outbound_proxy).await {
                log::debug!("Connection {addr:?} error: {e}");
            }
        });
    }
}

fn create_tls_config(
    sni: Option<&str>,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<(Arc<ServerConfig>, Arc<Vec<String>>), BoxError> {
    // If both cert and key paths provided, load them from PEM files
    if let (Some(cert_p), Some(key_p)) = (cert_path, key_path) {
        let cert_file = std::fs::File::open(cert_p)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let certs_iter = rustls_pemfile::certs(&mut cert_reader);
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> = certs_iter.collect::<Result<_, _>>()?;

        let key_file = std::fs::File::open(key_p)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        let key_der = rustls_pemfile::private_key(&mut key_reader)?.ok_or("failed to parse a supported private key")?;

        if certs.is_empty() {
            return Err("failed to parse cert PEM".into());
        }

        let allowlist = Arc::new(extract_dns_names_from_certs(&certs, sni));
        let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = certs.clone();
        let key = key_der;

        let config = ServerConfig::builder().with_no_client_auth().with_single_cert(cert_chain, key)?;

        return Ok((Arc::new(config), allowlist));
    }

    // Fallback: generate ephemeral cert (existing behavior)
    let cert = mkcert::generate_key_pair(sni.unwrap_or(""))?;
    Ok((Arc::new(cert), Arc::new(sni.into_iter().map(str::to_string).collect())))
}

fn create_probe_target_tls_config() -> Result<Arc<ClientConfig>, BoxError> {
    let mut root_store = RootCertStore::empty();
    let cert_result = rustls_native_certs::load_native_certs();
    if !cert_result.errors.is_empty() {
        log::warn!("Failed to load some native certs: {:?}", cert_result.errors);
    }

    for cert in cert_result.certs {
        root_store.add(cert)?;
    }

    let config = ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    Ok(Arc::new(config))
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    password_sha256: Vec<u8>,
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    probe_sni_allowlist: Arc<Vec<String>>,
    outbound_socks5: Option<ProxyParameters>,
) -> Result<(), BoxError> {
    let client_addr = stream.peer_addr()?;
    let mut tls_stream = acceptor.accept(stream).await?;
    let probe_target = tls_stream.get_ref().1.server_name().map(|server_name| server_name.to_owned());

    // Read authentication
    let mut auth_data = [0u8; 34]; // 32 bytes password + 2 bytes padding length
    let mut auth_bytes_read = 0;
    while auth_bytes_read < auth_data.len() {
        let n = tls_stream.read(&mut auth_data[auth_bytes_read..]).await?;
        if n == 0 {
            break;
        }
        auth_bytes_read += n;
    }

    let received_password_matches = auth_bytes_read == auth_data.len() && auth_data[..32] == *password_sha256.as_slice();

    if !received_password_matches {
        if let Some(target_host) = probe_target.filter(|target| sni_is_allowed(target, &probe_sni_allowlist)) {
            if let Err(err) = relay_probe_stream(client_addr, target_host, tls_stream, auth_data[..auth_bytes_read].to_vec()).await {
                log::debug!("Probe relay failed for {client_addr}: {err}");
            }
        } else {
            log::debug!("Authentication failed for {client_addr}, and probe SNI did not match the server certificate name");
        }
        return Ok(());
    }

    let padding_len = u16::from_be_bytes([auth_data[32], auth_data[33]]);
    let client_id = if padding_len > 0 {
        let mut padding_data = vec![0u8; padding_len as usize];
        tls_stream.read_exact(&mut padding_data).await?;
        extract_client_id_from_padding(&padding_data)
    } else {
        None
    };

    if let Some(client_id) = client_id {
        log::debug!("Authenticated client {client_addr} id={client_id}");
    } else {
        log::debug!("Authenticated client {client_addr}");
    }

    // Create session
    let session = new_server_session(
        Box::new(tls_stream),
        Box::new(move |session| {
            // Handle new session (logical stream)
            let outbound_socks5 = outbound_socks5.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_session(client_addr, session, outbound_socks5).await {
                    log::debug!("Session error: {}", e);
                }
            });
        }),
        padding,
    )
    .await;

    log::debug!("Connection {client_addr:?}: session created, entering run loop");
    session.run().await?;
    log::debug!("Connection {client_addr:?}: session run loop exited");
    Ok(())
}

fn extract_client_id_from_padding(padding_data: &[u8]) -> Option<Uuid> {
    const UUID_STR_LEN: usize = 36;

    if padding_data.len() < UUID_STR_LEN {
        return None;
    }

    let candidate = match std::str::from_utf8(&padding_data[..UUID_STR_LEN]) {
        Ok(text) => text.trim_end_matches('\0').trim(),
        Err(_) => return None,
    };

    if candidate.len() != UUID_STR_LEN {
        return None;
    }

    Uuid::parse_str(candidate).ok()
}

async fn relay_probe_stream<S>(client_addr: SocketAddr, target_host: String, mut tls_stream: S, prefix: Vec<u8>) -> Result<(), BoxError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let target_addr = format!("{}:443", target_host);
    log::info!("Fallback relay for {client_addr} to {target_addr}");

    let tcp_outbound = TcpStream::connect(&target_addr).await?;
    tcp_outbound.set_nodelay(true)?;
    let tls_config = create_probe_target_tls_config()?;
    let connector = TlsConnector::from(tls_config);
    let server_name: rustls::pki_types::ServerName<'static> = target_host.clone().try_into()?;
    let mut outbound = connector.connect(server_name, tcp_outbound).await?;

    outbound.write_all(&prefix).await?;
    outbound.flush().await?;

    let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut outbound).await?;
    Ok(())
}

fn extract_dns_names_from_certs(certs: &[rustls::pki_types::CertificateDer<'static>], fallback_sni: Option<&str>) -> Vec<String> {
    let mut names = Vec::new();

    if let Some(cert_chain) = certs.first()
        && let Ok((_, parsed_cert)) = x509_parser::parse_x509_certificate(cert_chain.as_ref())
    {
        for extension in parsed_cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
                for general_name in &san.general_names {
                    if let GeneralName::DNSName(dns_name) = general_name {
                        names.push(dns_name.to_string());
                    }
                }
            }
        }
    }

    if names.is_empty()
        && let Some(sni) = fallback_sni
    {
        names.push(sni.to_string());
    }

    names.sort();
    names.dedup();
    names
}

fn sni_is_allowed(target: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|allowed| allowed.eq_ignore_ascii_case(target))
}

async fn handle_session(client_addr: SocketAddr, session: Arc<Stream>, outbound_socks5: Option<ProxyParameters>) -> Result<(), BoxError> {
    let mut reader = StreamReader {
        inner: session.clone(),
        read_fut: None,
    };
    use socks5_impl::protocol::{Address, AsyncStreamOperation};
    loop {
        if session.is_terminated().await {
            return Ok(());
        }

        let destination = match Address::retrieve_from_async_stream(&mut reader).await {
            Ok(destination) => destination,
            Err(err) if session.is_terminated().await || is_error_of_session_broken(&err) => {
                log::debug!("Session handler exiting after stream end: {err}");
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };

        let outbound_socks5 = outbound_socks5.clone();
        if uot_is_sentinel_destination(&destination) {
            handle_uot_stream(session.clone(), client_addr, &mut reader, outbound_socks5).await?;
        } else {
            handle_tcp_stream(session.clone(), client_addr, destination, outbound_socks5).await?;
        }
    }
}

async fn handle_uot_stream(
    session: Arc<Stream>,
    client_addr: SocketAddr,
    reader: &mut StreamReader,
    outbound_socks5: Option<ProxyParameters>,
) -> Result<(), BoxError> {
    let request = uot_get_request_from_stream(reader).await?;
    match request.mode {
        UotMode::Connected => handle_uot_connected_stream(session, client_addr, reader, &request, outbound_socks5).await,
        UotMode::Datagram => handle_uot_datagram_stream(session, client_addr, reader, outbound_socks5).await,
    }
}

async fn handle_uot_datagram_stream(
    session: Arc<Stream>,
    client_addr: SocketAddr,
    reader: &mut StreamReader,
    outbound_socks5: Option<ProxyParameters>,
) -> Result<(), BoxError> {
    let sid = session.id();
    let mut outbound_buf = vec![0u8; 65_535];

    let outbound = create_uot_udp_outbound(sid.into(), outbound_socks5).await?;
    session.handshake_success().await?;

    let result: Result<(), BoxError> = async {
        loop {
            tokio::select! {
                res = uot_get_packet_from_stream(UotMode::Datagram, reader) => {
                    let (destination, payload) = match res {
                        Ok(packet) => packet,
                        Err(err) if is_error_of_session_broken(&err) => break Ok(()),
                        Err(err) => break Err(err.into()),
                    };
                    let destination = destination.expect("UOT datagram destination must be present");
                    log::info!("Session #{sid} UOT datagram from {client_addr} to {destination}");
                    send_uot_udp_payload(&outbound, &payload, &destination).await?;
                }
                res = recv_uot_udp_payload(&outbound, &mut outbound_buf) => {
                    let (n, source) = res?;
                    let frame = uot_encode_packet(UotMode::Datagram, Some(&source), &outbound_buf[..n])?;
                    session.write(&frame).await?;
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
    session: Arc<Stream>,
    client: SocketAddr,
    reader: &mut StreamReader,
    request: &UotRequest,
    outbound_socks5: Option<ProxyParameters>,
) -> Result<(), BoxError> {
    let sid = session.id();
    let outbound = create_uot_udp_outbound(sid.into(), outbound_socks5).await?;

    let fixed_destination = request.destination.to_string();
    if let Err(err) = ensure_uot_udp_outbound_ready(&outbound, &request.destination).await {
        log::debug!("Failed to prepare UDP outbound to {fixed_destination}: {err}");
        session.handshake_failure(&err.to_string()).await?;
        session.terminate().await?;
        return Err(err.into());
    }

    session.handshake_success().await?;
    log::info!("Session #{sid} UOT connected session established from {client} to {fixed_destination}");

    let mut outbound_buf = vec![0u8; 65_535];

    let result: Result<(), BoxError> = async {
        loop {
            tokio::select! {
                res = uot_get_packet_from_stream(UotMode::Connected, reader) => {
                    let (_, payload) = match res {
                        Ok(packet) => packet,
                        Err(err) if is_error_of_session_broken(&err) => break Ok(()),
                        Err(err) => break Err(err.into()),
                    };
                    send_uot_udp_payload(&outbound, &payload, &request.destination).await?;
                }
                res = recv_uot_udp_payload(&outbound, &mut outbound_buf) => {
                    let (n, _) = res?;
                    let frame = uot_encode_packet(UotMode::Connected, None, &outbound_buf[..n])?;
                    session.write(&frame).await?;
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

async fn handle_tcp_stream(
    session: Arc<Stream>,
    client: SocketAddr,
    destination: socks5_impl::protocol::Address,
    outbound_socks5: Option<ProxyParameters>,
) -> Result<(), BoxError> {
    let sid = session.id();
    log::debug!("Connecting to {}", destination);
    let mut outbound = match connect_outbound_tcp(&destination, outbound_socks5.clone()).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("Failed to connect to {destination}: {e}");
            session.handshake_failure(&e.to_string()).await?;
            session.terminate().await?;
            return Err(e.into());
        }
    };
    let dest = if let Some(proxy_addr) = outbound_socks5 {
        format!("{destination} via {proxy_addr}")
    } else if let Ok(peer_addr) = outbound.peer_addr() {
        format!("{peer_addr}({destination})")
    } else {
        destination.to_string()
    };
    log::info!("Session #{sid} TCP relay established from {client} to {dest}");

    // Report success
    session.handshake_success().await?;

    log::debug!("Starting relay to destination {destination}");
    // Relay data
    let stream_read = session.clone();
    let stream_write = session.clone();
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
            if is_error_of_session_broken(e) {
                log::debug!("Error relaying to outbound {}: {e}", destination);
            } else {
                log::warn!("Error relaying to outbound {}: {e}", destination);
            }
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
                        stream_write.close().await?;
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
            if is_error_of_session_broken(e) {
                log::debug!("Error relaying from outbound {}: {e}", destination);
            } else {
                log::warn!("Error relaying from outbound {}: {e}", destination);
            }
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

fn is_error_of_session_broken(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe)
}

enum UotUdpOutbound {
    Direct(UdpSocket),
    Proxied(SocksUdpClient),
}

async fn create_uot_udp_outbound(sid: u64, outbound_socks5: Option<ProxyParameters>) -> std::io::Result<UotUdpOutbound> {
    if let Some(proxy_params) = outbound_socks5 {
        log::debug!("Session #{sid} using SOCKS5 UDP outbound via {proxy_params}");
        let proxy_addr: SocketAddr = proxy_params.addr.try_into()?;
        Ok(UotUdpOutbound::Proxied(
            create_udp_client(proxy_addr, proxy_params.credentials).await?,
        ))
    } else {
        Ok(UotUdpOutbound::Direct(UdpSocket::bind("0.0.0.0:0").await?))
    }
}

async fn ensure_uot_udp_outbound_ready(outbound: &UotUdpOutbound, destination: &Address) -> std::io::Result<()> {
    match outbound {
        UotUdpOutbound::Direct(socket) => socket.connect(destination.to_string()).await,
        UotUdpOutbound::Proxied(_) => Ok(()),
    }
}

async fn send_uot_udp_payload(outbound: &UotUdpOutbound, payload: &[u8], destination: &Address) -> std::io::Result<usize> {
    match outbound {
        UotUdpOutbound::Direct(socket) => socket.send_to(payload, destination.to_string()).await,
        UotUdpOutbound::Proxied(client) => client.send_to(payload, destination.clone()).await.map_err(std::io::Error::other),
    }
}

async fn recv_uot_udp_payload(outbound: &UotUdpOutbound, outbound_buf: &mut [u8]) -> std::io::Result<(usize, Address)> {
    match outbound {
        UotUdpOutbound::Direct(socket) => {
            let (n, source) = socket.recv_from(outbound_buf).await?;
            Ok((n, Address::from(source)))
        }
        UotUdpOutbound::Proxied(client) => {
            let mut raw = vec![0u8; outbound_buf.len()];
            let timeout = std::time::Duration::from_secs(5);
            let r = client.recv_from(timeout, &mut raw).await.map_err(std::io::Error::other)?;
            raw.truncate(r.0);
            outbound_buf[..r.0].copy_from_slice(&raw);
            Ok(r)
        }
    }
}

async fn connect_outbound_tcp(destination: &Address, outbound_socks5: Option<ProxyParameters>) -> std::io::Result<TcpStream> {
    if let Some(parameters) = outbound_socks5 {
        let proxy_addr: SocketAddr = parameters.addr.try_into()?;
        let mut stream = TcpStream::connect(proxy_addr).await?;
        client::connect(&mut stream, destination.clone(), parameters.credentials).await?;
        Ok(stream)
    } else {
        TcpStream::connect(destination.to_string()).await
    }
}
