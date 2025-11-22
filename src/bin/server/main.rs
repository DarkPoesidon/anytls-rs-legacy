use anytls_rs::proxy::padding::DefaultPaddingFactory;
use anytls_rs::proxy::session::Session;
use anytls_rs::util::{mkcert, PROGRAM_VERSION_NAME};
use clap::Parser;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
#[command(name = "anytls-server", about = "AnyTLS Server")]
struct Args {
    #[arg(short = 'l', long, default_value = "0.0.0.0:8443", help = "Server listen port")]
    listen: String,

    #[arg(short = 'p', long, help = "Password")]
    password: String,

    #[arg(long, help = "Padding scheme file")]
    padding_scheme: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            log::info!("Loaded padding scheme file: {}", padding_file);
        } else {
            log::error!("Wrong format padding scheme file: {}", padding_file);
            std::process::exit(1);
        }
    }

    log::info!("[Server] {}", PROGRAM_VERSION_NAME);
    log::info!("[Server] Listening TCP {}", args.listen);

    let listener = TcpListener::bind(&args.listen).await?;

    let tls_config = create_tls_config()?;
    let acceptor = TlsAcceptor::from(tls_config);
    let padding = DefaultPaddingFactory::load();

    loop {
        let (stream, addr) = listener.accept().await?;
        log::debug!("Accepted connection from: {}", addr);
        let acceptor = acceptor.clone();
        let padding = padding.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, acceptor, password_sha256.to_vec(), padding).await {
                log::debug!("Connection error: {}", e);
            }
        });
    }
}

fn create_tls_config() -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let cert = mkcert::generate_key_pair("")?;
    Ok(Arc::new(cert))
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    password_sha256: Vec<u8>,
    padding: Arc<tokio::sync::RwLock<anytls_rs::proxy::padding::PaddingFactory>>,
) -> Result<(), Box<dyn std::error::Error>> {
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

async fn read_exact(stream: &anytls_rs::proxy::session::Stream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        let n = stream.read(&mut buf[pos..]).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Stream closed"));
        }
        pos += n;
    }
    Ok(())
}

async fn handle_stream(stream: Arc<anytls_rs::proxy::session::Stream>) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!("Handling new stream: {}", stream.id());
    // Read destination address (SOCKS format)
    // 1 byte type + address + 2 bytes port
    let mut header = [0u8; 1];
    read_exact(&stream, &mut header).await?;

    let target_addr: String;
    let target_port: u16;

    match header[0] {
        1 => {
            // IPv4
            let mut buf = [0u8; 4 + 2];
            read_exact(&stream, &mut buf).await?;
            target_addr = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            target_port = u16::from_be_bytes([buf[4], buf[5]]);
        }
        3 => {
            // Domain
            let mut len_buf = [0u8; 1];
            read_exact(&stream, &mut len_buf).await?;
            let len = len_buf[0] as usize;

            let mut buf = vec![0u8; len + 2];
            read_exact(&stream, &mut buf).await?;

            target_addr = String::from_utf8_lossy(&buf[..len]).to_string();
            target_port = u16::from_be_bytes([buf[len], buf[len + 1]]);
        }
        4 => {
            // IPv6
            let mut buf = [0u8; 16 + 2];
            read_exact(&stream, &mut buf).await?;
            let addr = std::net::Ipv6Addr::from(u128::from_be_bytes(buf[..16].try_into().unwrap()));
            target_addr = addr.to_string();
            target_port = u16::from_be_bytes([buf[16], buf[17]]);
        }
        _ => return Err("Unsupported address type".into()),
    }

    let destination = format!("{}:{}", target_addr, target_port);
    log::debug!("Connecting to {}", destination);

    let mut outbound = match TcpStream::connect(&destination).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("Failed to connect to {}: {}", destination, e);
            stream.close().await?;
            return Err(e.into());
        }
    };

    // Report success
    stream.handshake_success().await?;

    log::debug!("Starting relay for stream {}", stream.id());
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
        loop {
            match stream_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = outbound_write.write_all(&buf[..n]).await {
                        log::debug!("Outbound write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    log::debug!("Stream read error: {}", e);
                    break;
                }
            }
        }
        let _ = outbound_write.shutdown().await;
    };

    let o2s = async {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 4096];
        loop {
            match outbound_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = stream_write.write(&buf[..n]).await {
                        log::debug!("Stream write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    log::debug!("Outbound read error: {}", e);
                    break;
                }
            }
        }
        let _ = stream_write.close().await;
    };

    tokio::join!(s2o, o2s);

    log::debug!("Relay finished for stream {}", stream.id());

    Ok(())
}
