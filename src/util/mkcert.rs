use anyhow::Result;
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;

pub fn generate_key_pair(server_name: &str) -> Result<ServerConfig> {
    let cert = generate_simple_self_signed(vec![server_name.to_string()])?;
    let cert_der = cert.cert.der();
    let key_der = cert.key_pair.serialize_der();

    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.to_vec())];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));

    let config = ServerConfig::builder().with_no_client_auth().with_single_cert(cert_chain, key)?;

    Ok(config)
}
