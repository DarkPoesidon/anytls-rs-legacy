use std::net::IpAddr;

pub async fn retrieve_public_ip() -> std::io::Result<IpAddr> {
    let ipv4_urls = [
        "https://api.ipify.org?format=text",
        "https://ifconfig.me",
        "https://icanhazip.com",
        "https://api-ipv4.ip.sb/ip",
    ];

    for url in ipv4_urls {
        if let Ok(resp) = reqwest::get(url).await
            && let Ok(text) = resp.text().await
        {
            let ip = text.trim();
            if ip.contains('.') && !ip.contains(':') {
                return ip.parse().map_err(std::io::Error::other);
            }
        }
    }

    let ipv6_urls = [
        "https://api6.ipify.org?format=text",
        "https://ipv6.icanhazip.com",
        "https://api-ipv6.ip.sb/ip",
    ];

    for url in ipv6_urls {
        if let Ok(resp) = reqwest::get(url).await
            && let Ok(text) = resp.text().await
        {
            let ip = text.trim();
            if ip.contains(':') {
                return ip.parse().map_err(std::io::Error::other);
            }
        }
    }

    Err(std::io::Error::other("Cannot retrieve public IP"))
}
