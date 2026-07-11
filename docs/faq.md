# Frequently Asked Questions

## General Questions

### What is AnyTLS?

AnyTLS is a proxy protocol designed to mitigate TLS in TLS fingerprinting issues. It uses flexible packet splitting and padding strategies to make traffic patterns less detectable.

### Why Rust?

This is a Rust implementation of the AnyTLS protocol, providing better performance and memory safety compared to the original Go implementation.

### How does it work?

AnyTLS works by:

1. Establishing a TLS connection between client and server
2. Using custom padding schemes to obfuscate traffic patterns
3. Implementing connection reuse to reduce latency
4. Supporting both TCP and UDP (via UDP over TCP) proxying

## Installation

### Building from Source

```bash
git clone https://github.com/anytls/anytls-rs
cd anytls-rs
cargo build --release
```

### Dependencies

- Rust 1.70+
- OpenSSL or equivalent TLS library
- Tokio runtime

## Configuration

### Client Configuration

```bash
./anytls-client -l 127.0.0.1:1080 -s server:443 -p password
```

### Server Configuration

```bash
./anytls-server -l 0.0.0.0:443 -p password
```

### Advanced Options

- `--sni`: Set SNI for TLS connection
- `--padding-scheme`: Load custom padding scheme file
- `--log-level`: Set logging level

## Troubleshooting

### Connection Issues

1. Check firewall settings
2. Verify server address and port
3. Ensure password matches between client and server
4. Check TLS certificate validity

### Performance Issues

1. Adjust padding scheme for your network conditions
2. Tune connection reuse parameters
3. Monitor memory usage and connection counts

### Debugging

Enable debug logging:

```bash
RUST_LOG=debug ./anytls-client -l 127.0.0.1:1080 -s server:443 -p password
```

## Protocol Compatibility

### Version Support

- Protocol Version 1: Basic functionality
- Protocol Version 2: Enhanced timeout handling and heartbeat

### Client Compatibility

- AnyTLS-RS Client: Full support
- Sing-box: Via anytls plugin
- Mihomo: Via anytls plugin
- Shadowrocket: 2.2.65+

## Security Considerations

### Password Security

- Use strong, random passwords
- Consider using environment variables for passwords
- Rotate passwords regularly

### TLS Security

- Use valid TLS certificates
- Consider using custom CA certificates
- Monitor for certificate expiration

### Network Security

- Run server behind firewall
- Use non-standard ports when possible
- Monitor for unusual traffic patterns

## Performance Tuning

### Connection Reuse

Adjust these parameters for your use case:

- `idleSessionCheckInterval`: How often to check for idle sessions
- `idleSessionTimeout`: How long to keep idle sessions
- `minIdleSession`: Minimum number of idle sessions to maintain

### Padding Scheme

Customize padding scheme based on:

- Network latency
- Bandwidth requirements
- Detection avoidance needs

## Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Style

- Follow Rust conventions
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Add documentation for public APIs

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

- GitHub Issues: For bug reports and feature requests
- Discussions: For general questions and community support
- Documentation: Check the docs/ directory for detailed information
