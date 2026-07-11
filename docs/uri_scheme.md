# URI Scheme Documentation

## Overview

AnyTLS uses a URI-based configuration format to describe the basic information needed to connect to an AnyTLS server.

## URI Format

```text
anytls://[auth@]hostname[:port]/?[key=value]&[key=value]...
```

## Components

### Scheme

`anytls`

### Auth

The authentication password is placed in the URI `auth` field. This is the standard URI username component, so any special characters should be URL-encoded.

### Host

The server hostname or IP address. If the port is omitted, the default is `443`.

### Parameters

- `sni`: TLS server name indication. If the `sni` value is an IP address, the client must not send SNI.
- `insecure`: Whether to allow an insecure TLS connection. Accepts `1` for `true` and `0` for `false`.

### Fragment

The part after `#` is the fragment. In AnyTLS, the fragment is used as the node's display name.

- Fragment content must be URL-encoded so spaces and special characters are parsed and transmitted correctly.
- Clients should URL-decode the fragment to obtain a readable node name or label.
- Example: `#my%20tag%20with%20spaces` decodes to `my tag with spaces`.

## Examples

```text
anytls://letmein@example.com/?sni=real.example.com
anytls://letmein@example.com/?sni=127.0.0.1&insecure=1
anytls://0fdf77d7-d4ba-455e-9ed9-a98dd6d5489a@[2409:8a71:6a00:1953::615]:8964/?sni=real.example.com
anytls://letmein@example.com/?sni=real.example.com#my%20tag%20with%20spaces
anytls://letmein@[fe80::abcd:1234]/?sni=real.example.com
anytls://letmein@[fe80::abcd:1234]:8080/?sni=real.example.com
anytls://letmein@[fe80::abcd:1234%eth0]:8080/?sni=real.example.com
```

## Notes

This URI intentionally contains only the basic information needed to connect to an AnyTLS server. Third-party implementations may add extra parameters if needed, but they should not assume that other implementations understand those extra parameters.

## URL Encoding

Special characters in auth and other values should be URL-encoded.

## Default Values

- Port: `443`
- SNI: hostname if not specified
