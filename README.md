# AnyTLS-RS

A Rust implementation of the [AnyTLS](https://github.com/anytls/anytls-go) proxy protocol that attempts to mitigate the TLS in TLS fingerprinting problem.

AnyTLS-RS provides a proxy solution that disguises proxy traffic as regular TLS connections,
making it harder to detect and block.

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

### Custom Ports

Server on port 443:
```bash
./anytls-server -l 0.0.0.0:443 -p mysecret
```

Client connecting to custom server:
```bash
./anytls-client -s example.com:443 -p mysecret
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

## Contributing

Contributions are welcome! Please open issues and pull requests on GitHub.

## License

MIT License - see [LICENSE](LICENSE) file for details.
