use anytls_rs::proxy::padding::DefaultPaddingFactory;
use anytls_rs::proxy::session::Session;
use anytls_rs::{BoxError, PROGRAM_VERSION_NAME, util::mkcert};
use clap::Parser;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
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
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    env_logger::init();

    let args = Args::parse();

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

    loop {
        let (stream, addr) = listener.accept().await?;
        log::debug!("Accepted connection from: {}", addr);

        let _ = stream.set_nodelay(true);
        let sock_ref = socket2::SockRef::from(&stream);
        let mut ka = socket2::TcpKeepalive::new();
        ka = ka.with_time(std::time::Duration::from_secs(60));
        ka = ka.with_interval(std::time::Duration::from_secs(10));
        let _ = sock_ref.set_tcp_keepalive(&ka);

        let acceptor = acceptor.clone();
        let padding = padding.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, acceptor, password_sha256.to_vec(), padding).await {
                log::debug!("Connection error: {}", e);
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
    stream: TcpStream,
    acceptor: TlsAcceptor,
    password_sha256: Vec<u8>,
    padding: Arc<tokio::sync::RwLock<anytls_rs::proxy::padding::PaddingFactory>>,
) -> Result<(), BoxError> {
    let mut tls_stream = acceptor.accept(stream).await?;

    // Read authentication
    let mut auth_data = vec![0u8; 34]; // 32 bytes password + 2 bytes padding length
    tls_stream.read_exact(&mut auth_data).await?;

    let received_password = &auth_data[..32];
    if received_password != password_sha256.as_slice() {
        log::debug!("Authentication failed for {}", tls_stream.get_ref().0.peer_addr()?);
        return Ok(());
    }
    log::debug!("Authentication successful for {}", tls_stream.get_ref().0.peer_addr()?);

    let padding_len = u16::from_be_bytes([auth_data[32], auth_data[33]]);
    if padding_len > 0 {
        let mut padding_data = vec![0u8; padding_len as usize];
        tls_stream.read_exact(&mut padding_data).await?;
    }

    // Create session
    let session = Session::new_server(
        Box::new(tls_stream),
        Box::new(|stream| {
            // Handle new stream
            tokio::spawn(async move {
                if let Err(e) = handle_stream(stream).await {
                    log::debug!("Stream error: {}", e);
                }
            });
        }),
        padding,
    );

    session.run().await?;
    Ok(())
}

async fn handle_stream(stream: Arc<anytls_rs::proxy::session::Stream>) -> Result<(), BoxError> {
    log::debug!("Handling new stream: {}", stream.id());
    // Read destination address (SOCKS format)

    struct StreamReader {
        inner: Arc<anytls_rs::proxy::session::Stream>,
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

    let mut reader = StreamReader {
        inner: stream.clone(),
        read_fut: None,
    };
    use socks5_impl::protocol::{Address, AsyncStreamOperation};
    let destination = Address::retrieve_from_async_stream(&mut reader).await?.to_string();

    log::debug!("Connecting to {}", destination);
    let mut outbound = match TcpStream::connect(&destination).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("Failed to connect to {destination}: {e}");
            stream.close().await?;
            return Err(e.into());
        }
    };

    // Report success
    stream.handshake_success().await?;

    let stream_id = stream.id();
    log::debug!("Starting relay for stream {stream_id} to destination {destination}");
    // Relay data
    let (stream_read, stream_write) = stream.split_ref();
    let (mut outbound_read, mut outbound_write) = outbound.split();

    // Use a custom copy loop for Stream -> Outbound because Stream doesn't implement AsyncRead in a way compatible with copy
    // Wait, Stream implements AsyncRead but it's a placeholder.
    // We need to use the read method directly or fix AsyncRead.
    // Since we have split_ref returning Self, and Self has read(), let's use a custom loop.

    let s2o = async {
        use tokio::io::AsyncWriteExt;
        let mut buf = vec![0u8; 4096];
        let res = loop {
            match stream_read.read(&mut buf).await {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    if let Err(e) = outbound_write.write_all(&buf[..n]).await {
                        break Err(e);
                    }
                }
                Err(e) => break Err(e),
            }
        };
        if let Err(e) = res {
            log::warn!("Error relaying from stream {stream_id} to outbound: {e}");
        }
        outbound_write.shutdown().await?;
        log::debug!("Stream {stream_id} s2o finished (client->outbound)");
        Ok::<(), std::io::Error>(())
    };

    let o2s = async {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 4096];
        let res = loop {
            match outbound_read.read(&mut buf).await {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    if let Err(e) = stream_write.write(&buf[..n]).await {
                        break Err(e);
                    }
                }
                Err(e) => break Err(e),
            }
        };
        if let Err(e) = res {
            log::warn!("Error relaying from outbound to stream {stream_id}: {e}");
        }
        stream_write.close().await?;
        log::debug!("Stream {stream_id} o2s finished (outbound->client)");
        Ok::<(), std::io::Error>(())
    };

    match tokio::join!(s2o, o2s) {
        (Ok(_), Ok(_)) => log::debug!("Relay finished for stream {stream_id}"),
        (Err(e), _) | (_, Err(e)) => log::warn!("Relay error for stream {stream_id}: {e}"),
    }

    Ok(())
}
