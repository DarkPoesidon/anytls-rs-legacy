//! Loopback management API for a panel-supervised node.
//!
//! The panel owns the user list and the traffic ledger; this node owns the live
//! sessions. The API is the seam between them, and it is deliberately shaped
//! like the sidecar API 3x-ui already speaks to its `mtg` process, so the panel
//! side is a manager of the familiar kind:
//!
//! | Method | Path                        | Purpose                                      |
//! |--------|-----------------------------|----------------------------------------------|
//! | GET    | `/healthz`                  | readiness probe                              |
//! | GET    | `/stats`                    | absolute per-user counters and live conns    |
//! | PUT    | `/users`                    | replace the user set in place                |
//! | POST   | `/users/{email}/reset-quota`| start a new quota window for one user        |
//!
//! Counters are reported as absolute, monotonic totals; the panel computes
//! deltas between scrapes. That way a scrape the panel misses costs nothing, and
//! a node restart shows up as counters going backwards, which the panel's delta
//! maths clamps to zero rather than double-counting.
//!
//! The listener must stay on loopback: `PUT /users` can replace every
//! credential the node serves, so the bearer token is the only thing standing
//! between another local process and the node's user set.

use crate::node_api::users::{UserRegistry, UserSpec};
use http_body_util::{BodyExt, Full};
use hyper::body::Body as _;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Largest `PUT /users` body accepted, enough for a few thousand users.
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// One user's live counters, as scraped by the panel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatsUser {
    /// Connections currently open for this user; a positive value means online.
    pub connections: i64,
    /// Absolute bytes received from the client since this process started.
    pub bytes_in: u64,
    /// Absolute bytes sent to the client since this process started.
    pub bytes_out: u64,
    /// Bytes counted against the current quota window.
    pub quota_used: u64,
    /// Quota in bytes, or zero when unlimited.
    pub quota_bytes: u64,
    /// Expiry as unix seconds, or zero when the user never expires.
    pub expires_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatsResponse {
    pub users: HashMap<String, StatsUser>,
}

/// One user in a `PUT /users` body. Mirrors [`UserSpec`] minus the email, which
/// is the map key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsersPutEntry {
    pub password: String,
    #[serde(default)]
    pub quota_bytes: u64,
    #[serde(default)]
    pub expires_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsersPutBody {
    pub users: HashMap<String, UsersPutEntry>,
}

impl UsersPutBody {
    /// Flatten the request body into registry specs, ordered by email so a
    /// password collision is resolved the same way on every node.
    pub fn into_specs(self) -> Vec<UserSpec> {
        let mut specs: Vec<UserSpec> = self
            .users
            .into_iter()
            .map(|(email, entry)| UserSpec {
                email,
                password: entry.password,
                quota_bytes: entry.quota_bytes,
                expires_unix: entry.expires_unix,
            })
            .collect();
        specs.sort_by(|a, b| a.email.cmp(&b.email));
        specs
    }
}

/// Snapshot every user's counters for a `GET /stats` response.
pub fn collect_stats(registry: &UserRegistry) -> StatsResponse {
    let users = registry
        .entries()
        .into_iter()
        .map(|entry| {
            let stats = StatsUser {
                connections: entry.connections(),
                bytes_in: entry.bytes_up(),
                bytes_out: entry.bytes_down(),
                quota_used: entry.quota_used(),
                quota_bytes: entry.quota_bytes(),
                expires_unix: entry.expires_unix(),
            };
            (entry.email().to_string(), stats)
        })
        .collect();
    StatsResponse { users }
}

/// Configuration for the management listener. Absent `bind` disables the API.
#[derive(Debug, Clone, Default)]
pub struct ApiConfig {
    pub bind: Option<SocketAddr>,
    pub token: Option<String>,
}

fn json_response(status: StatusCode, body: impl Serialize) -> Response<Full<Bytes>> {
    let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(payload)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"{}"))))
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, serde_json::json!({ "error": message }))
}

/// Check the bearer token when one is configured.
fn authorized(req: &Request<Incoming>, token: Option<&str>) -> bool {
    let Some(token) = token else {
        return true;
    };
    let Some(header) = req.headers().get(hyper::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = header.to_str() else {
        return false;
    };
    let presented = value.strip_prefix("Bearer ").unwrap_or(value);
    // Length-independent compare so a wrong token leaks nothing through timing.
    let (a, b) = (presented.as_bytes(), token.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Path suffix of a reset-quota request, with the email percent-decoded.
fn reset_quota_target(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/users/")?.strip_suffix("/reset-quota")?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(rest).decode_utf8().ok()?;
    Some(decoded.into_owned())
}

/// Infallible by construction: every failure is answered with a status code, so
/// hyper never has to invent one.
async fn handle(
    req: Request<Incoming>,
    registry: Arc<UserRegistry>,
    token: Option<Arc<str>>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    Ok(route(req, registry, token).await)
}

async fn route(req: Request<Incoming>, registry: Arc<UserRegistry>, token: Option<Arc<str>>) -> Response<Full<Bytes>> {
    if !authorized(&req, token.as_deref()) {
        return error_response(StatusCode::UNAUTHORIZED, "invalid or missing bearer token");
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (&method, path.as_str()) {
        (&Method::GET, "/healthz") => json_response(StatusCode::OK, serde_json::json!({ "status": "ok" })),
        (&Method::GET, "/stats") => json_response(StatusCode::OK, collect_stats(&registry)),
        (&Method::PUT, "/users") => {
            let upper = req.body().size_hint().upper().unwrap_or(u64::MAX);
            if upper > MAX_BODY_BYTES {
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
            }
            let bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("cannot read body: {e}")),
            };
            let body: UsersPutBody = match serde_json::from_slice(&bytes) {
                Ok(body) => body,
                Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
            };
            let specs = body.into_specs();
            registry.replace(&specs);
            log::info!("management API applied user set of {} entries", registry.len());
            json_response(StatusCode::OK, serde_json::json!({ "users": registry.len() }))
        }
        (&Method::POST, _) if reset_quota_target(&path).is_some() => {
            let email = reset_quota_target(&path).unwrap_or_default();
            match registry.get(&email) {
                Some(entry) => {
                    entry.reset_quota();
                    log::info!("management API reset the quota window of {email}");
                    json_response(StatusCode::OK, serde_json::json!({ "email": email }))
                }
                None => error_response(StatusCode::NOT_FOUND, "unknown user"),
            }
        }
        _ => error_response(StatusCode::NOT_FOUND, "no such endpoint"),
    }
}

/// Serve the management API until `quit` is cancelled.
///
/// Returns the bound address, which lets a caller that asked for port 0 learn
/// what it actually got.
pub async fn serve(
    config: ApiConfig,
    registry: Arc<UserRegistry>,
    quit: CancellationToken,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let bind = config
        .bind
        .ok_or_else(|| std::io::Error::other("management API bind address not set"))?;
    if !bind.ip().is_loopback() {
        log::warn!("management API is bound to {bind}, which is not loopback; it can replace every credential this node serves");
    }
    let listener = TcpListener::bind(bind).await?;
    let local_addr = listener.local_addr()?;
    let token: Option<Arc<str>> = config.token.as_deref().map(Arc::from);
    if token.is_none() {
        log::warn!("management API on {local_addr} has no token; any local process can rewrite this node's user set");
    }
    log::info!("[Server] Management API listening on {local_addr}");

    let handle = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = quit.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    log::warn!("management API accept failed: {e}");
                    continue;
                }
            };
            let registry = registry.clone();
            let token = token.clone();
            let quit = quit.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| handle(req, registry.clone(), token.clone()));
                let conn = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service);
                tokio::pin!(conn);
                let result = tokio::select! {
                    _ = quit.cancelled() => {
                        conn.as_mut().graceful_shutdown();
                        conn.await
                    }
                    result = conn.as_mut() => result,
                };
                if let Err(e) = result {
                    log::debug!("management API connection from {peer} ended: {e}");
                }
            });
        }
        log::debug!("management API stopped");
    });

    Ok((local_addr, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_api::users::hash_password;

    fn registry_with(users: &[(&str, &str)]) -> Arc<UserRegistry> {
        let specs: Vec<UserSpec> = users
            .iter()
            .map(|(email, password)| UserSpec {
                email: email.to_string(),
                password: password.to_string(),
                quota_bytes: 0,
                expires_unix: 0,
            })
            .collect();
        Arc::new(UserRegistry::with_users(&specs))
    }

    async fn request(addr: SocketAddr, method: &str, path: &str, token: Option<&str>, body: Option<&str>) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = body.unwrap_or_default();
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(token) = token {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        let status = raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
        (status, body)
    }

    async fn start(registry: Arc<UserRegistry>, token: Option<&str>) -> (SocketAddr, CancellationToken) {
        let quit = CancellationToken::new();
        let config = ApiConfig {
            bind: Some("127.0.0.1:0".parse().unwrap()),
            token: token.map(str::to_string),
        };
        let (addr, _) = serve(config, registry, quit.clone()).await.unwrap();
        (addr, quit)
    }

    #[tokio::test]
    async fn stats_reports_counters_and_live_connections() {
        let registry = registry_with(&[("a@x", "pw-a")]);
        let session = registry.authenticate(&hash_password("pw-a")).unwrap();
        session.record_up(120);
        session.record_down(340);
        let (addr, quit) = start(registry, None).await;

        let (status, body) = request(addr, "GET", "/stats", None, None).await;
        assert_eq!(status, 200);
        let parsed: StatsResponse = serde_json::from_str(&body).unwrap();
        let user = &parsed.users["a@x"];
        assert_eq!(user.bytes_in, 120);
        assert_eq!(user.bytes_out, 340);
        assert_eq!(user.connections, 1);
        quit.cancel();
    }

    #[tokio::test]
    async fn put_users_replaces_the_set_in_place() {
        let registry = registry_with(&[("a@x", "pw-a"), ("b@x", "pw-b")]);
        let a_session = registry.authenticate(&hash_password("pw-a")).unwrap();
        let (addr, quit) = start(registry.clone(), None).await;

        let body = r#"{"users":{"a@x":{"password":"pw-a"},"c@x":{"password":"pw-c","quota_bytes":50}}}"#;
        let (status, _) = request(addr, "PUT", "/users", None, Some(body)).await;
        assert_eq!(status, 200);

        assert_eq!(a_session.deny_reason(), None, "an untouched client keeps its connection");
        assert!(registry.authenticate(&hash_password("pw-b")).is_none());
        assert!(registry.authenticate(&hash_password("pw-c")).is_some());
        assert_eq!(registry.get("c@x").unwrap().quota_bytes(), 50);
        quit.cancel();
    }

    #[tokio::test]
    async fn reset_quota_reopens_a_spent_user() {
        let registry = Arc::new(UserRegistry::with_users(&[UserSpec {
            email: "a@x".to_string(),
            password: "pw-a".to_string(),
            quota_bytes: 100,
            expires_unix: 0,
        }]));
        registry.authenticate(&hash_password("pw-a")).unwrap().record_up(150);
        assert!(registry.authenticate(&hash_password("pw-a")).is_none());
        let (addr, quit) = start(registry.clone(), None).await;

        let (status, _) = request(addr, "POST", "/users/a%40x/reset-quota", None, None).await;
        assert_eq!(status, 200);
        assert!(registry.authenticate(&hash_password("pw-a")).is_some());
        quit.cancel();
    }

    #[tokio::test]
    async fn token_is_required_when_configured() {
        let registry = registry_with(&[("a@x", "pw-a")]);
        let (addr, quit) = start(registry, Some("s3cret")).await;

        assert_eq!(request(addr, "GET", "/stats", None, None).await.0, 401);
        assert_eq!(request(addr, "GET", "/stats", Some("wrong"), None).await.0, 401);
        assert_eq!(request(addr, "GET", "/stats", Some("s3cret"), None).await.0, 200);
        quit.cancel();
    }

    #[tokio::test]
    async fn unknown_paths_and_users_are_reported() {
        let registry = registry_with(&[("a@x", "pw-a")]);
        let (addr, quit) = start(registry, None).await;

        assert_eq!(request(addr, "GET", "/nope", None, None).await.0, 404);
        assert_eq!(request(addr, "POST", "/users/ghost/reset-quota", None, None).await.0, 404);
        assert_eq!(request(addr, "PUT", "/users", None, Some("not json")).await.0, 400);
        quit.cancel();
    }

    #[test]
    fn reset_quota_path_is_parsed_strictly() {
        assert_eq!(reset_quota_target("/users/a%40x/reset-quota").as_deref(), Some("a@x"));
        assert_eq!(reset_quota_target("/users//reset-quota"), None);
        assert_eq!(reset_quota_target("/users/a/b/reset-quota"), None);
        assert_eq!(reset_quota_target("/users/a@x"), None);
    }
}
