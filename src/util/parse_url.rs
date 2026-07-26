use crate::BoxError;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str};
use socks5_impl::protocol::Address;
use std::net::SocketAddr;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ClientRuntimeConfig {
    pub server: Address,
    pub password: String,
    pub sni: Option<String>,
    pub client_id: Option<Uuid>,
    pub insecure: bool,
    pub display_name: Option<String>,
}

impl ClientRuntimeConfig {
    pub fn authority(&self) -> String {
        format_authority(&self.server)
    }

    pub fn to_anytls_url(&self) -> String {
        let mut host = self.server.domain();
        if host.contains('%') {
            host = host.replace('%', "%25");
        }
        if self.server.is_ipv6() || host.contains(':') {
            host = format!("[{}]", host);
        }

        let authority = if self.server.port() == 443 {
            host
        } else {
            format!("{}:{}", host, self.server.port())
        };

        let mut uri = String::from("anytls://");
        if !self.password.is_empty() {
            uri.push_str(&percent_encode_userinfo(&self.password));
            uri.push('@');
        }
        uri.push_str(&authority);

        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(sni) = &self.sni {
            query.append_pair("sni", sni);
        }
        if self.insecure {
            query.append_pair("insecure", "1");
        }
        if let Some(client_id) = &self.client_id {
            query.append_pair("client_id", &client_id.to_string());
        }
        let query = query.finish();
        if !query.is_empty() {
            uri.push_str("/?");
            uri.push_str(&query);
        }

        if let Some(display_name) = &self.display_name {
            uri.push('#');
            uri.push_str(&percent_encode_fragment(display_name));
        }

        uri
    }
}

pub fn format_authority(address: &Address) -> String {
    match address {
        Address::SocketAddress(addr) => addr.to_string(),
        Address::DomainAddress(host, port) => {
            if host.contains(':') {
                format!("[{}]:{}", host, port)
            } else {
                format!("{}:{}", host, port)
            }
        }
    }
}

fn is_anytls_ipv6_zone_url(raw_url: &str) -> bool {
    let raw = raw_url.strip_prefix("anytls://").unwrap_or(raw_url);
    let authority_end = raw.find(['/', '?', '#']).unwrap_or(raw.len());
    let authority = &raw[..authority_end];
    let auth_and_host = if let Some(at_pos) = authority.rfind('@') {
        &authority[at_pos + 1..]
    } else {
        authority
    };
    let host_start = match auth_and_host.find('[') {
        Some(pos) => pos,
        None => return false,
    };
    let host_end = match auth_and_host[host_start..].find(']') {
        Some(pos) => host_start + pos,
        None => return false,
    };
    auth_and_host[host_start..host_end].contains('%')
}

pub fn parse_anytls_url(raw_url: &str) -> Result<ClientRuntimeConfig, BoxError> {
    if is_anytls_ipv6_zone_url(raw_url) {
        return parse_anytls_url_ipv6_zone(raw_url);
    }

    let url = Url::parse(raw_url)?;
    if url.scheme() != "anytls" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "URL scheme must be anytls").into());
    }

    let server = match url.host() {
        Some(url::Host::Domain(domain)) => Address::DomainAddress(domain.to_string().into_boxed_str(), url.port().unwrap_or(443)),
        Some(url::Host::Ipv4(addr)) => Address::SocketAddress(SocketAddr::from((addr, url.port().unwrap_or(443)))),
        Some(url::Host::Ipv6(addr)) => Address::SocketAddress(SocketAddr::from((addr, url.port().unwrap_or(443)))),
        None => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "AnyTLS URL must include a host").into());
        }
    };

    let mut password = url.username().to_owned();
    if password.is_empty() {
        password = url.password().unwrap_or_default().to_owned();
    }

    let query = url.query().unwrap_or("");
    let fragment = url.fragment();

    build_client_runtime_config(server, password, query, fragment)
}

fn build_client_runtime_config(
    server: Address,
    password: String,
    query: &str,
    fragment: Option<&str>,
) -> Result<ClientRuntimeConfig, BoxError> {
    use std::io::{Error, ErrorKind::InvalidInput};
    let mut sni = None;
    let display_name = fragment
        .map(|frag| percent_decode_str(frag).decode_utf8_lossy().into_owned())
        .filter(|frag| !frag.is_empty());
    let mut insecure = false;
    let mut client_id = None;

    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "password" => {
                return Err(Error::new(
                    InvalidInput,
                    "Password must be provided in the URI auth field, not in query parameters",
                )
                .into());
            }
            "sni" => sni = Some(value.into_owned()),
            "insecure" => match value.as_ref() {
                "1" => insecure = true,
                "0" => insecure = false,
                other => {
                    return Err(Error::new(InvalidInput, format!("Invalid insecure value in AnyTLS URL: {other}")).into());
                }
            },
            "client_id" if !value.is_empty() => {
                client_id = Some(value.parse::<Uuid>()?);
            }
            _ => {}
        }
    }

    Ok(ClientRuntimeConfig {
        server,
        password,
        sni,
        client_id,
        insecure,
        display_name,
    })
}

fn parse_anytls_url_ipv6_zone(raw_url: &str) -> Result<ClientRuntimeConfig, BoxError> {
    use std::io::{Error, ErrorKind::InvalidInput};
    const SCHEME: &str = "anytls://";
    let without_scheme = raw_url
        .strip_prefix(SCHEME)
        .ok_or_else(|| Error::new(InvalidInput, "URL scheme must be anytls"))?;

    let (userinfo, authority_and_rest) = if let Some(at_pos) = without_scheme.find('@') {
        (&without_scheme[..at_pos], &without_scheme[at_pos + 1..])
    } else {
        ("", without_scheme)
    };

    let host_start = authority_and_rest
        .find('[')
        .ok_or_else(|| Error::new(InvalidInput, "AnyTLS URL must include a host"))?;
    let host_end = authority_and_rest
        .find(']')
        .ok_or_else(|| Error::new(InvalidInput, "Invalid IPv6 host in AnyTLS URL"))?;
    let mut server_host = authority_and_rest[host_start + 1..host_end].to_owned();
    if server_host.contains("%25") {
        server_host = percent_decode_str(&server_host).decode_utf8_lossy().into_owned();
    }

    let after = &authority_and_rest[host_end + 1..];
    let (server_port, rest) = if let Some(after_colon) = after.strip_prefix(':') {
        let delim = after_colon.find(|c| ['/', '?', '#'].contains(&c)).unwrap_or(after_colon.len());
        let port_text = &after_colon[..delim];
        let port = port_text
            .parse::<u16>()
            .map_err(|e| Error::new(InvalidInput, format!("Invalid port in AnyTLS URL: {e}")))?;
        (port, &after_colon[delim..])
    } else {
        (443, after)
    };

    let password = if let Some(colon_pos) = userinfo.find(':') {
        let username = &userinfo[..colon_pos];
        if !username.is_empty() {
            username.to_owned()
        } else {
            userinfo[colon_pos + 1..].to_owned()
        }
    } else {
        userinfo.to_owned()
    };

    let query = if let Some(question_pos) = rest.find('?') {
        let query_fragment = &rest[question_pos + 1..];
        if let Some(hash_pos) = query_fragment.find('#') {
            &query_fragment[..hash_pos]
        } else {
            query_fragment
        }
    } else {
        ""
    };

    let display_name = rest.split_once('#').and_then(|(_, frag)| {
        let frag = frag.trim();
        if frag.is_empty() {
            None
        } else {
            Some(percent_decode_str(frag).decode_utf8_lossy().into_owned())
        }
    });

    let server = if server_host.contains('%') {
        Address::DomainAddress(server_host.into_boxed_str(), server_port)
    } else if let Ok(socket) = format!("[{}]:{}", server_host, server_port).parse::<SocketAddr>() {
        Address::SocketAddress(socket)
    } else {
        Address::DomainAddress(server_host.into_boxed_str(), server_port)
    };

    build_client_runtime_config(server, password, query, display_name.as_deref())
}

const USERINFO_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn percent_encode_userinfo(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, USERINFO_ENCODE_SET).to_string()
}

const FRAGMENT_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');

fn percent_encode_fragment(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, FRAGMENT_ENCODE_SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_anytls_url_with_userinfo_and_query_params() {
        let raw_url = "anytls://mypassword@example.com?sni=example.com&insecure=1#node%201";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "example.com");
        assert_eq!(config.server.port(), 443);
        assert_eq!(config.password, "mypassword");
        assert_eq!(config.sni.as_deref(), Some("example.com"));
        assert!(config.insecure);
        assert_eq!(config.display_name.as_deref(), Some("node 1"));
        assert_eq!(config.authority(), "example.com:443");
    }

    #[test]
    fn rejects_password_query_parameter() {
        let raw_url = "anytls://letmein@example.com/?password=bad&key=val";
        assert!(parse_anytls_url(raw_url).is_err());
    }

    #[test]
    fn parses_anytls_url_with_ipv6_host_without_port() {
        let raw_url = "anytls://[fe80::abcd:1234]/?sni=real.example.com";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "fe80::abcd:1234");
        assert_eq!(config.server.port(), 443);
        assert_eq!(config.sni.as_deref(), Some("real.example.com"));
        assert!(!config.insecure);
    }

    #[test]
    fn parses_anytls_url_with_ipv6_host_and_port() {
        let raw_url = "anytls://[fe80::abcd:1234]:8080/?sni=real.example.com";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "fe80::abcd:1234");
        assert_eq!(config.server.port(), 8080);
        assert_eq!(config.sni.as_deref(), Some("real.example.com"));
    }

    #[test]
    fn parses_anytls_url_with_auth_and_ipv6_host_without_port() {
        let raw_url = "anytls://letmein@[fe80::abcd:1234]/?sni=real.example.com";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "fe80::abcd:1234");
        assert_eq!(config.server.port(), 443);
        assert_eq!(config.password, "letmein");
        assert_eq!(config.sni.as_deref(), Some("real.example.com"));
    }

    #[test]
    fn parses_anytls_url_with_auth_and_ipv6_host_and_port() {
        let raw_url = "anytls://letmein@[fe80::abcd:1234]:8080/?sni=real.example.com";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "fe80::abcd:1234");
        assert_eq!(config.server.port(), 8080);
        assert_eq!(config.password, "letmein");
        assert_eq!(config.sni.as_deref(), Some("real.example.com"));
    }

    #[test]
    fn parses_anytls_url_with_auth_and_ipv6_zone_id() {
        let raw_url = "anytls://letmein@[fe80::abcd:1234%eth0]:8080/?sni=real.example.com";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "fe80::abcd:1234%eth0");
        assert_eq!(config.server.port(), 8080);
        assert_eq!(config.password, "letmein");
        assert_eq!(config.sni.as_deref(), Some("real.example.com"));
    }

    #[test]
    fn parses_anytls_url_with_query_containing_at_sign() {
        let raw_url = "anytls://letmein@[fe80::abcd:1234%eth0]:8080/?sni=real@example.com";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "fe80::abcd:1234%eth0");
        assert_eq!(config.server.port(), 8080);
        assert_eq!(config.password, "letmein");
        assert_eq!(config.sni.as_deref(), Some("real@example.com"));
        assert!(!config.insecure);
    }

    #[test]
    fn parses_anytls_url_with_query_and_fragment_after_ipv6_zone_id() {
        let raw_url = "anytls://letmein@[fe80::abcd:1234%eth0]:8080/?key1=dfsdf&key2=werwrwerwre#frag";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "fe80::abcd:1234%eth0");
        assert_eq!(config.server.port(), 8080);
        assert_eq!(config.password, "letmein");
        assert_eq!(config.sni.as_deref(), None);
        assert_eq!(config.display_name.as_deref(), Some("frag"));
    }

    #[test]
    fn parses_anytls_url_with_encoded_ipv6_zone_id() {
        let raw_url = "anytls://[fe80::abcd:1234%25eth0]:8080/?sni=real.example.com";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "fe80::abcd:1234%eth0");
        assert_eq!(config.server.port(), 8080);
        assert_eq!(config.sni.as_deref(), Some("real.example.com"));
        assert!(!config.insecure);
    }

    #[test]
    fn parses_anytls_url_dup() {
        let raw_url = "anytls://mypassword@example.com:943?#node%201";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "example.com");
        assert_eq!(config.server.port(), 943);
        assert_eq!(config.password, "mypassword");
        assert_eq!(config.display_name.as_deref(), Some("node 1"));
    }

    #[test]
    fn to_anytls_url_includes_dup() {
        let config = ClientRuntimeConfig {
            server: Address::DomainAddress(String::from("example.com").into_boxed_str(), 443),
            password: "mypassword".to_string(),
            sni: Some("example.com".to_string()),
            insecure: true,
            display_name: Some("node 1".to_string()),
            ..Default::default()
        };

        let uri = config.to_anytls_url();
        assert!(uri.contains("insecure=1"));
        assert!(uri.ends_with("#node%201"));
    }

    #[test]
    fn to_anytls_url_skips_empty_password() {
        let config = ClientRuntimeConfig {
            server: Address::DomainAddress(String::from("example.com").into_boxed_str(), 443),
            sni: Some("example.com".to_string()),
            ..Default::default()
        };

        let uri = config.to_anytls_url();
        assert_eq!(uri, "anytls://example.com/?sni=example.com");
    }

    #[test]
    fn to_anytls_url_omits_default_port_for_ipv6() {
        let config = ClientRuntimeConfig {
            server: Address::DomainAddress(String::from("fe80::abcd:1234").into_boxed_str(), 443),
            password: "mypassword".to_string(),
            sni: Some("real.example.com".to_string()),
            ..Default::default()
        };

        let uri = config.to_anytls_url();
        assert_eq!(uri, "anytls://mypassword@[fe80::abcd:1234]/?sni=real.example.com");
    }

    #[test]
    fn to_anytls_url_encodes_ipv6_zone_id() {
        let config = ClientRuntimeConfig {
            server: Address::DomainAddress(String::from("fe80::abcd:1234%eth0").into_boxed_str(), 8080),
            password: "mypassword".to_string(),
            sni: Some("real.example.com".to_string()),
            ..Default::default()
        };

        let uri = config.to_anytls_url();
        assert!(uri.contains("[fe80::abcd:1234%25eth0]:8080"));
        assert!(uri.contains("sni=real.example.com"));
    }

    #[test]
    fn parses_auth_from_username_and_defaults_port_443() {
        let raw_url = "anytls://mypassword@example.com?sni=example.com&foo=bar&insecure=0";
        let config = parse_anytls_url(raw_url).expect("URL should parse");

        assert_eq!(config.server.domain(), "example.com");
        assert_eq!(config.server.port(), 443);
        assert_eq!(config.password, "mypassword");
        assert_eq!(config.sni.as_deref(), Some("example.com"));
        assert!(!config.insecure);
        assert_eq!(config.display_name.as_deref(), None);
        assert_eq!(config.authority(), "example.com:443");
    }
}
