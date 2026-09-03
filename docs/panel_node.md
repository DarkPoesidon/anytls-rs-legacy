# Running as a panel-managed node

`anytls-server` has two ways to serve more than one user. They are mutually
exclusive, and the server refuses to start if both are configured.

| | sspanel webapi sync | Multi-user node (this document) |
|---|---|---|
| Flags | `--panel-webapi-url/-token/-node-id` | `--users-file`, `--api-bind-to`, `--api-token` |
| Direction | node polls the panel | panel pushes to the node |
| Credential | one shared password | one password per user |
| Identity | `client_id` UUID in the auth padding | the password itself |
| Client support | only clients that send `client_id` | any AnyTLS client |
| Limits enforced | enable/disable | enable/disable, byte quota, expiry |

Multi-user mode exists because the shared-password scheme cannot be trusted for
accounting: the `client_id` is unauthenticated metadata, so any holder of the
shared password can claim to be any user. Giving each user its own password
makes the 32 auth bytes every AnyTLS client already sends the identity, which
also means stock clients (sing-box, mihomo, Shadowrocket) work unchanged.

## Starting a node

```bash
anytls-server \
  -l 0.0.0.0:443 \
  --sni example.com --cert /etc/anytls/fullchain.pem --key /etc/anytls/privkey.pem \
  --users-file /etc/anytls/users.json \
  --api-bind-to 127.0.0.1:8443 \
  --api-token "$(openssl rand -hex 16)"
```

`--users-file` is read once at startup so a restarted node serves its users
immediately, without waiting for the panel. After that the management API is the
live source of truth.

```json
{
  "users": {
    "alice@example.com": { "password": "s3cret", "quota_bytes": 0, "expires_unix": 0 },
    "bob@example.com":   { "password": "s3cr3t", "quota_bytes": 107374182400, "expires_unix": 1780000000 }
  }
}
```

`quota_bytes` is the combined up + down allowance, counted from the last quota
reset; `0` means unlimited. `expires_unix` is in seconds; `0` means never.

## Management API

Bound to loopback, and authenticated with `Authorization: Bearer <token>`.
`PUT /users` can replace every credential the node serves, so treat the token
like a root password and never bind the API to a public address.

### `GET /healthz`

```json
{ "status": "ok" }
```

### `GET /stats`

```json
{
  "users": {
    "alice@example.com": {
      "connections": 2,
      "bytes_in": 91234,
      "bytes_out": 8812345,
      "quota_used": 8903579,
      "quota_bytes": 0,
      "expires_unix": 0
    }
  }
}
```

`bytes_in` is what the client uploaded, `bytes_out` what it downloaded, both as
**absolute totals since the process started**. The caller computes deltas between
scrapes, which makes a missed scrape harmless; a node restart shows up as the
counters going backwards, which a caller clamping negative deltas to zero reads
as "no traffic" rather than double-counting.

`connections` is the number of TLS connections the user has open right now, so a
positive value means the user is online.

Counters cover relayed payload bytes, not TLS record or padding overhead, so
they read a little under what the interface counter sees.

### `PUT /users`

Replaces the whole user set in one shot, in place:

```json
{ "users": { "alice@example.com": { "password": "s3cret", "quota_bytes": 0, "expires_unix": 0 } } }
```

- A user whose password is unchanged keeps its connections **and** its counters,
  so editing one client never disturbs the others.
- A user whose password changed keeps its counters, and its existing connections
  are dropped.
- A user missing from the body is revoked: its live sessions are cut within a
  second and it disappears from `/stats`.

Two users may not share a password — the node would have no way to tell their
traffic apart — so a colliding entry is dropped with a warning.

### `POST /users/{email}/reset-quota`

Starts a new quota window for one user, without rewinding the reported totals.
Use it when the panel resets a client's traffic. The email must be
percent-encoded (`alice%40example.com`).

## What a cut-off user sees

A user that is revoked, expired, or over quota has its live sessions terminated
within about a second, and any new connection fails authentication. Requests in
flight end with an empty response rather than an explicit refusal — there is no
way to signal "quota exceeded" inside the AnyTLS protocol.
