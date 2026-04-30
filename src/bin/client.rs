use anytls::AsyncReadWrite;
use anytls::core::PaddingFactory;
use anytls::proxy::session::{Client, Session};
use anytls::runtime::DefaultPaddingFactory;
use anytls::uot::{UotMode, UotRequest, uot_encode_packet, uot_get_packet_from_stream, uot_sentinel_destination};
use anytls::{BoxError, PROGRAM_VERSION_NAME};
use clap::Parser;
use rustls::ClientConfig;
use sha2::{Digest, Sha256};
use socks5_impl::server::auth::NoAuth;
use socks5_impl::server::connection::associate;
use socks5_impl::server::{AssociatedUdpSocket, IncomingConnection, Server, UdpAssociate};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_535;

#[derive(Parser)]
#[command(version, author, name = "anytls-client", about = "AnyTLS Client")]
struct Args {
    #[arg(short = 'l', long, default_value = "127.0.0.1:1080", help = "SOCKS5 listen port")]
    listen: SocketAddr,

    #[arg(short = 's', long, help = "Server address")]
    server: SocketAddr,

    #[arg(long, help = "SNI")]
    sni: Option<String>,

    #[arg(short = 'p', long, help = "Password")]
    password: String,

    #[arg(long, help = "Root CA certificate PEM file to verify server (optional)")]
    root_cert: Option<PathBuf>,

    #[arg(long, default_value = "info", help = "Log level (off, error, warn, info, debug, trace)")]
    log: log::LevelFilter,
}

struct StreamReader {
    inner: Arc<Session>,
    #[allow(clippy::type_complexity)]
    read_fut: Option<std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<(Vec<u8>, usize)>> + Send>>>,
}

impl StreamReader {
    fn new(inner: Arc<Session>) -> Self {
        Self { inner, read_fut: None }
    }
}

impl AsyncRead for StreamReader {
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
        println!("Ctrl+C received, cancelling...");
        cancel_token_clone.cancel();
        true
    })?;

    let main_worker = tokio::spawn(run(cancel_token));

    ctrlc_future.await?;
    main_worker.await??;

    Ok(())
}

async fn run(cancel_token: tokio_util::sync::CancellationToken) -> Result<(), BoxError> {
    let args = Args::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(args.log.to_string())).init();

    if args.password.is_empty() {
        log::error!("Please set password");
        std::process::exit(1);
    }

    let password_sha256: [u8; 32] = Sha256::digest(args.password.as_bytes()).into();

    log::info!("[Client] {}", PROGRAM_VERSION_NAME);
    log::info!("[Client] SOCKS5 {} => {}", args.listen, args.server);

    let server = Server::bind(args.listen, Arc::new(NoAuth)).await?;

    let tls_config = create_tls_config(args.root_cert.as_deref())?;
    let padding = DefaultPaddingFactory::load();

    let padding_clone = padding.clone();
    let client = Arc::new(Client::new(
        Box::new(move || {
            Box::pin(dail_out_callback(
                args.server,
                args.sni.clone(),
                tls_config.clone(),
                padding_clone.clone(),
                password_sha256,
            ))
        }),
        padding,
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(30),
        5,
    ));
    let connection_id = Arc::new(AtomicU64::new(0));

    loop {
        let cancel_token = cancel_token.clone();
        let connection_id = connection_id.clone();

        let (stream, _addr) = tokio::select! {
            _ = cancel_token.cancelled() => {
                log::info!("Shutting down server...");
                break Ok(());
            }
            res = server.accept() => res?,
        };

        let client = client.clone();

        tokio::spawn(async move {
            let conn_id = connection_id.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = handle_connection(conn_id, stream, client).await {
                log::error!("Connection #{conn_id} error: {e}");
            }
        });
    }
}

async fn dail_out_callback(
    server: SocketAddr,
    sni: Option<String>,
    tls_config: Arc<ClientConfig>,
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    password_sha256: [u8; 32],
) -> std::io::Result<Box<dyn AsyncReadWrite>> {
    let sni = sni.clone();
    let stream = TcpStream::connect(&server).await?;
    stream.set_nodelay(true)?;
    let ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(10));
    socket2::SockRef::from(&stream).set_tcp_keepalive(&ka)?;

    use rustls::pki_types::ServerName;
    let server_name = if let Some(sni) = sni {
        if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            // For domain, use owned string
            use std::io::{Error, ErrorKind::InvalidInput};
            ServerName::try_from(sni).map_err(|e| Error::new(InvalidInput, e))?
        }
    } else {
        ServerName::IpAddress(server.ip().into())
    };

    let connector = TlsConnector::from(tls_config);
    let mut tls_stream = connector.connect(server_name, stream).await?;

    // Send authentication
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&password_sha256);

    let padding_factory = padding.read().await;
    let padding_sizes = padding_factory.generate_record_payload_sizes(0);
    let padding_len = if !padding_sizes.is_empty() { padding_sizes[0] as u16 } else { 0 };

    auth_data.extend_from_slice(&padding_len.to_be_bytes());
    if padding_len > 0 {
        auth_data.resize(auth_data.len() + padding_len as usize, 0);
    }

    // Send auth data
    tls_stream.write_all(&auth_data).await?;

    Ok(Box::new(tls_stream) as Box<dyn AsyncReadWrite>)
}

fn create_tls_config(root_cert: Option<&Path>) -> Result<Arc<ClientConfig>, BoxError> {
    // If a root certificate file is provided, load it and use it for verification.
    if let Some(path) = root_cert {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let certs_iter = rustls_pemfile::certs(&mut reader);
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> = certs_iter.collect::<Result<_, _>>()?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert)?;
        }

        let config = ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();

        return Ok(Arc::new(config));
    }

    // No root cert provided: fall back to dangerous accept-any behavior (legacy)
    let mut config = ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    config.dangerous().set_certificate_verifier(Arc::new(AllowAnyCertVerifier));

    Ok(Arc::new(config))
}

// 允许任何证书的验证器
#[derive(Debug)]
struct AllowAnyCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AllowAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

async fn handle_connection(conn_id: u64, incoming: IncomingConnection<()>, client: Arc<Client>) -> Result<(), BoxError> {
    // perform handshake/authentication
    let (authenticated, _out) = incoming.authenticate().await?;
    let client_conn = authenticated.wait_request().await?;

    use socks5_impl::protocol::Reply;
    use socks5_impl::server::connection::ClientConnection;

    match client_conn {
        ClientConnection::Connect(conn_need_reply, addr) => {
            // Reply to client with success and upgrade to Ready
            let conn_ready = conn_need_reply.reply(Reply::Succeeded, addr.clone()).await?;
            s5_connect(conn_id, conn_ready, addr, client).await?;
        }
        ClientConnection::UdpAssociate(associate, _) => {
            handle_udp_associate(conn_id, associate, client).await?;
        }
        ClientConnection::Bind(_, _) => {
            log::warn!("Bind command is not supported");
            return Err("Bind command is not supported".into());
        }
    };
    Ok(())
}

async fn s5_connect(
    conn_id: u64,
    conn_ready: socks5_impl::server::connection::connect::Connect<socks5_impl::server::connection::connect::Ready>,
    target_addr: socks5_impl::protocol::Address,
    client: Arc<Client>,
) -> std::io::Result<()> {
    log::info!("Connection #{conn_id}: connecting to target via proxy: {}", target_addr);

    // 创建到代理服务器的连接
    let proxy_stream = client.create_stream().await?;
    {
        // Debug: check is_closed first, then take pointer (as integer) and log in a short scope
        let is_closed = proxy_stream.is_closed().await;
        let session_ptr_val = Arc::as_ptr(&proxy_stream) as usize;
        log::debug!("Connection #{conn_id}: acquired proxy session ptr=0x{session_ptr_val:x} is_closed={is_closed}",);
    }

    // 发送目标地址给代理服务器
    let addr_data: Vec<u8> = target_addr.into();
    let written = proxy_stream.write(&addr_data).await?;
    log::debug!(
        "Connection #{conn_id}: wrote target addr {} bytes to proxy (expected {})",
        written,
        addr_data.len()
    );

    // 开始数据转发
    let (mut client_read, mut client_write) = conn_ready.into_split();
    let proxy_stream_read = proxy_stream.clone();
    let proxy_stream_write = proxy_stream.clone();

    // Client -> Proxy
    let c2p = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut err = None;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    log::trace!("s5_connect: client->proxy forwarding {} bytes", n);
                    if let Err(e) = proxy_stream_write.write(&buf[..n]).await {
                        err = Some(e);
                        break;
                    }
                }
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let _ = proxy_stream_write.close().await;
        if let Some(e) = err {
            log::debug!("Connection #{conn_id}: client to proxy error: {e}");
        }
    });

    // Proxy -> Client
    let p2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut err = None;
        loop {
            match proxy_stream_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    log::trace!("s5_connect: proxy->client forwarding {} bytes", n);
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        err = Some(e);
                        break;
                    }
                }
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let _ = client_write.shutdown().await;
        if let Some(e) = err {
            log::debug!("Connection #{conn_id}: proxy to client error: {e}");
        }
    });

    let _ = tokio::join!(c2p, p2c);

    Ok(())
}

async fn handle_udp_associate(conn_id: u64, associate: UdpAssociate<associate::NeedReply>, client: Arc<Client>) -> Result<(), BoxError> {
    use socks5_impl::protocol::{Address, Reply};

    let listen_ip = associate.local_addr()?.ip();
    let udp_listener = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;

    let (udp_listener, listen_addr) = match udp_listener.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Ok(v) => v,
        Err(err) => {
            let mut reply_listener = associate.reply(Reply::GeneralFailure, Address::unspecified()).await?;
            reply_listener.shutdown().await?;
            return Err(err.into());
        }
    };

    let proxy_stream = match client.create_stream().await {
        Ok(stream) => stream,
        Err(err) => {
            let mut reply_listener = associate.reply(Reply::GeneralFailure, Address::unspecified()).await?;
            reply_listener.shutdown().await?;
            return Err(err.into());
        }
    };

    if let Err(err) = async {
        log::debug!("Connection #{conn_id}: starting UDP associate");
        let outer_addr: Vec<u8> = uot_sentinel_destination().into();
        proxy_stream.write(&outer_addr).await?;

        let request_bytes: Vec<u8> = UotRequest::new(UotMode::Datagram, Address::unspecified()).into();
        proxy_stream.write(&request_bytes).await?;

        Ok::<(), BoxError>(())
    }
    .await
    {
        let _ = proxy_stream.close().await;
        let mut reply_listener = associate.reply(Reply::GeneralFailure, Address::unspecified()).await?;
        reply_listener.shutdown().await?;
        return Err(err);
    }

    let mut reply_listener = associate.reply(Reply::Succeeded, Address::from(listen_addr)).await?;
    let listen_udp = Arc::new(AssociatedUdpSocket::from((udp_listener, MAX_UDP_RELAY_PACKET_SIZE)));
    let zero_ip = match listen_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let incoming_addr = Arc::new(tokio::sync::Mutex::new(SocketAddr::from((zero_ip, 0))));
    let proxy_writer = proxy_stream.clone();
    let mut proxy_reader = StreamReader::new(proxy_stream.clone());

    let result: Result<(), BoxError> = loop {
        tokio::select! {
            res = listen_udp.recv_from() => {
                let (pkt, frag, destination, src_addr) = res?;
                if frag != 0 {
                    break Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "UDP fragmentation is not supported").into());
                }

                *incoming_addr.lock().await = src_addr;
                let frame = uot_encode_packet(UotMode::Datagram, Some(&destination), &pkt)?;
                proxy_writer.write(&frame).await?;
            }
            res = uot_get_packet_from_stream(UotMode::Datagram, &mut proxy_reader) => {
                let (source, payload) = res?;
                let incoming = *incoming_addr.lock().await;
                if incoming.port() == 0 {
                    continue;
                }

                listen_udp.send_to(&payload, 0, source.unwrap(), incoming).await?;
            }
            res = reply_listener.wait_until_closed() => {
                res?;
                break Ok(());
            }
        }
    };

    let _ = proxy_stream.close().await;
    let _ = reply_listener.shutdown().await;
    result
}
