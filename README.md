# AnyTLS-RS

[![CI](https://github.com/ssrlive/anytls-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/ssrlive/anytls-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/anytls.svg)](https://crates.io/crates/anytls)
[![docs.rs](https://img.shields.io/docsrs/anytls)](https://docs.rs/anytls)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust implementation of the [AnyTLS](https://github.com/anytls/anytls-go) proxy protocol that attempts to mitigate the TLS in TLS fingerprinting problem.

AnyTLS-RS provides a proxy solution that disguises proxy traffic as regular TLS connections,
making it harder to detect and block.

> Note: As of version 0.3.x, anytls-rs no longer provides multiplexing for the original protocol,
> in order to avoid its inherent complexity, fragility, and risk of deadlocks.
> Instead, it utilizes the connection pooling concept already present in the original protocol
> -- a mechanism that is entirely sufficient for high-concurrency applications.

## Features

- **TLS Obfuscation**: Masks proxy traffic as standard TLS connections
- **Flexible Padding**: Configurable packet splitting and padding strategies
- **Connection Reuse**: Reduces latency by reusing connections
- **Cross-Platform**: Supports Linux, macOS, and Windows
- **Certificate Support**: Optional custom TLS certificates for server and root CA for client
- **SOCKS5 Proxy**: Client acts as a SOCKS5 proxy for applications

## Installation

### From Source

Ensure you have Rust installed (https://rustup.rs/), then:

```bash
git clone https://github.com/ssrlive/anytls-rs.git
cd anytls-rs
cargo build --release
```

The binaries will be in `target/release/`.

### Pre-built Binaries

Download from the [releases page](https://github.com/ssrlive/anytls-rs/releases).

## Usage

### Server

Start the AnyTLS server:

```bash
./anytls-server --password your_password
```

The server listens on `0.0.0.0:8443` by default.

### Client

Start the AnyTLS client as a SOCKS5 proxy:

```bash
./anytls-client --password your_password --server 127.0.0.1:8443
```

The client listens on `127.0.0.1:1080` by default. Configure your application to use `socks5://127.0.0.1:1080`.

## Options

### Server Options

- `-l, --listen <LISTEN>`: Server listen address (default: `0.0.0.0:8443`)
- `-p, --password <PASSWORD>`: Authentication password (required)
- `--padding-scheme <FILE>`: Path to padding scheme configuration file
- `--cert <FILE>`: Path to TLS certificate PEM file (optional)
- `--key <FILE>`: Path to TLS private key PEM file (optional, PKCS#8 or RSA format)

### Client Options

- `-l, --listen <LISTEN>`: SOCKS5 listen address (default: `127.0.0.1:1080`)
- `-s, --server <SERVER>`: Server address (default: `127.0.0.1:8443`)
- `-p, --password <PASSWORD>`: Authentication password (required)
- `--sni <SNI>`: Server Name Indication for TLS
- `--root-cert <FILE>`: Path to root CA certificate PEM file for server verification (optional)

## Examples

### Basic Setup

1. Start server:
   ```bash
   ./anytls-server -p mysecret
   ```

2. Start client:
   ```bash
   ./anytls-client -p mysecret
   ```

3. Configure your browser or application to use SOCKS5 proxy at `127.0.0.1:1080`.

### With Custom Certificates

1. Generate certificates (example using OpenSSL):
   ```bash
   # Generate CA
   openssl genrsa -out ca.key 2048
   openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.pem -subj "/CN=MyCA"

   # Generate server cert
   openssl genrsa -out server.key 2048
   openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
   openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365 -sha256

   # Convert to PKCS#8
   openssl pkcs8 -topk8 -nocrypt -in server.key -out server.pk8
   ```

2. Start server with cert:
   ```bash
   ./anytls-server -p mysecret --cert server.pem --key server.pk8
   ```

3. Start client with root CA:
   ```bash
   ./anytls-client -p mysecret --root-cert ca.pem
   ```

### Generate Test Certificate (Python)

If you need a quick self-signed cert for local testing, use the included Python helper:

```bash
python scripts/gen_cert.py
# Produces scripts/selfsigned.crt and scripts/selfsigned.key (10 year validity)
```

`smoke_test.py` will also invoke this helper automatically if certificates are missing.

### Custom Ports

Server on port 443:
```bash
./anytls-server -l 0.0.0.0:443 -p mysecret
```

Client connecting to custom server:
```bash
./anytls-client -s example.com:443 -p mysecret
```

## Smoke / Integration Test (local)

Run the end-to-end smoke/integration test (builds binaries, starts a test server and client, then fetches a backend page through the SOCKS5 proxy):

```bash
# Requires Python 3 and curl (on Windows, run in PowerShell or Git Bash)
python scripts/smoke_test.py
```

## Building

```bash
cargo build --release
```

For development:
```bash
cargo build
cargo test
```

## Documentation

- [User FAQ](./docs/faq.md)
- [Protocol Documentation](./docs/protocol.md)
- [URI Format](./docs/uri_scheme.md)
- [Code Documentation](./docs/code.md)

## Compatibility Strategy

This project exposes two protocol version symbols used during session negotiation: `PROTOCOL_VERSION` (current implementation version)
and `MIN_PROTOCOL_VERSION` (minimum accepted version for compatibility). See [docs/protocol.md](./docs/protocol.md) for details. In short:

- Clients advertise `v=<n>` in `cmdSettings`; servers record and echo back a compatible version (>= `MIN_PROTOCOL_VERSION`).
- Feature gates (such as `cmdSYNACK` and heartbeats) are enabled only when the negotiated version supports them.
- Keep `MIN_PROTOCOL_VERSION` at a previous stable value when bumping `PROTOCOL_VERSION` to allow staged rollouts and interoperability.
- Note: this release removes stream-level multiplexing — each `Session` exposes a single logical stream (`sid==1`). 
  Multiplexing was removed because it increased implementation complexity and fragility and made deadlocks more likely.
  If you rely on multiplexing in other implementations, coordinate rollouts or maintain a compatibility gateway.

## Contributing

Contributions are welcome! Please open issues and pull requests on GitHub.

## License

MIT License - see [LICENSE](LICENSE) file for details.
