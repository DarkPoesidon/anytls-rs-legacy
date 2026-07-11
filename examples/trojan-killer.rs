//! trojan-killer: A simple tool to detect Trojan traffic by analyzing HTTP CONNECT requests.
//! This program listens on a local port for incoming HTTP requests, identifies CONNECT requests, and monitors the data flow
//! to detect patterns consistent with Trojan traffic. It is designed to be used as an HTTP proxy for anytls-rs clients.
//!
//! This tool is copied from https://github.com/XTLS/Trojan-killer.git and just for auditing anytls-rs traffic.
//!
//! Usage:
//! 1. Run this program on a machine that can see the traffic you want to analyze
//! 2. Configure your anytls-rs client to use this program as an HTTP proxy (e.g., --probe-http-proxy <bind-addr>)
//! 3. Use browsers or other tools to browse the internet through the anytls-rs client
//! 4. Monitor the console output for detected Trojan traffic
//!
//! Note: This tool is for educational purposes only. Use it responsibly and legally.
//!

use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

const CCS: [u8; 6] = [20, 3, 3, 0, 1, 1];

#[derive(Debug, Default)]
struct State {
    uploading: bool,
    up_count: usize,
    downloading: bool,
    down_count: usize,
}

fn main() -> std::io::Result<()> {
    println!("Trojan-killer v1.0.0 started");

    let bind_addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:12345".to_string());
    let listener = TcpListener::bind(&bind_addr)?;
    println!("Listening on {}\n", listener.local_addr()?);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle(stream);
                });
            }
            Err(_) => continue,
        }
    }

    Ok(())
}

fn handle(stream: TcpStream) -> std::io::Result<()> {
    let (method, target_host, request_reader) = read_request(stream.try_clone()?)?;

    let state = if method.eq_ignore_ascii_case("CONNECT") {
        "accepted"
    } else {
        "rejected"
    };

    println!("{} from {} {} {}", timestamp(), stream.peer_addr()?, state, target_host);

    if state == "rejected" {
        return Ok(());
    }

    let server = TcpStream::connect(&target_host)?;
    let mut client_writer = stream.try_clone()?;
    client_writer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;

    let shared = Arc::new(Mutex::new(State::default()));

    let client_to_server_shared = Arc::clone(&shared);
    let target_host_for_client = target_host.clone();
    let mut client_reader = request_reader;
    let mut server_writer = server.try_clone()?;
    let client_to_server = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = match client_reader.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => n,
                Err(_) => return,
            };

            {
                let mut state = client_to_server_shared.lock().unwrap();
                if state.up_count == 0 && n >= 6 && buf[..6] == CCS {
                    state.uploading = true;
                }
                if state.uploading {
                    state.up_count += n;
                }
                if state.downloading {
                    state.downloading = false;
                    if state.up_count >= 650
                        && state.up_count <= 750
                        && ((state.down_count >= 170 && state.down_count <= 180) || (state.down_count >= 3000 && state.down_count <= 7500))
                    {
                        println!("{} is Trojan", target_host_for_client);
                    }
                }
            }

            if server_writer.write_all(&buf[..n]).is_err() {
                return;
            }
        }
    });

    let server_to_client_shared = Arc::clone(&shared);
    let mut server_reader = server;
    let mut client_writer_for_server = stream.try_clone()?;
    let server_to_client = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = match server_reader.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => n,
                Err(_) => return,
            };

            {
                let mut state = server_to_client_shared.lock().unwrap();
                if state.uploading {
                    state.uploading = false;
                    state.downloading = true;
                }
                if state.downloading {
                    state.down_count += n;
                }
            }

            if client_writer_for_server.write_all(&buf[..n]).is_err() {
                return;
            }
        }
    });

    let _ = client_to_server.join();
    let _ = server_to_client.join();

    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn read_request(stream: TcpStream) -> std::io::Result<(String, String, BufReader<TcpStream>)> {
    let mut reader = BufReader::new(stream);

    let mut first_line = String::new();
    if reader.read_line(&mut first_line)? == 0 {
        use std::io::ErrorKind::UnexpectedEof;
        return Err(std::io::Error::new(UnexpectedEof, "empty request"));
    }

    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    Ok((method, target, reader))
}

fn timestamp() -> String {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => format!("{}", duration.as_secs()),
        Err(_) => "0".to_string(),
    }
}
