#!/usr/bin/env bash
set -euo pipefail

Green="\033[32m"
Yellow="\033[33m"
Red="\033[31m"
ColorOff="\033[0m"

REPO_OWNER="ssrlive"
REPO_NAME="anytls-rs"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
INSTALL_DIR="${INSTALL_DIR:-/etc/anytls}"
SERVICE_UNIT_NAME="anytls-server.service"

usage() {
  cat <<'USAGE'
Usage:
  installer.sh install <fake-domain> <listen-port> [password]
  installer.sh uninstall

Commands:
  install     Download the latest anytls musl release, install binaries, and generate certs.
  uninstall   Remove installed binaries, certs, and the optional systemd unit.

Arguments:
  fake-domain  Domain used for certificate generation and SNI.
  listen-port  Server listen port.
  password     Optional server password. If omitted, a random password is generated.

Environment variables:
  BIN_DIR      Directory where binaries are installed (default: /usr/local/bin)
  INSTALL_DIR  Directory where certificates and service files are stored (default: /etc/anytls)
USAGE
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${Red}This script must be run as root or with sudo.${ColorOff}" >&2
    exit 1
  fi
}

resolve_hostaddr() {
  local hostaddr

  hostaddr=$(curl -4 -sS https://ip.sb 2>/dev/null || true)
  if [ -n "$hostaddr" ]; then
    printf '%s\n' "$hostaddr"
    return 0
  fi

  hostaddr=$(curl -6 -sS https://ip.sb 2>/dev/null || true)
  if [ -n "$hostaddr" ]; then
    printf '%s\n' "$hostaddr"
    return 0
  fi

  hostname -f 2>/dev/null || hostname
}

check_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo -e "${Red}Required command not found: $1${ColorOff}" >&2
    exit 1
  fi
}

detect_release_asset() {
  local os_name arch_name

  os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch_name=$(uname -m)

  case "$os_name" in
    linux) ;;
    *)
      echo -e "${Red}Unsupported operating system for this installer: $os_name${ColorOff}" >&2
      exit 1
      ;;
  esac

  case "$arch_name" in
    x86_64|amd64)
      arch_name="x86_64"
      ;;
    aarch64|arm64)
      arch_name="aarch64"
      ;;
    *)
      echo -e "${Red}Unsupported architecture for release download: $arch_name${ColorOff}" >&2
      exit 1
      ;;
  esac

  if [ "$arch_name" != "x86_64" ]; then
    echo -e "${Red}This installer expects the x86_64 musl release package.${ColorOff}" >&2
    exit 1
  fi

  printf '%s\n' "anytls-x86_64-unknown-linux-musl.tar.gz"
}

download_release() {
  check_command curl
  check_command tar

  local asset_name="${1:?asset name required}"
  local release_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/${asset_name}"
  local archive_path

  if [ -z "$asset_name" ] || [ "$asset_name" != "anytls-x86_64-unknown-linux-musl.tar.gz" ]; then
    echo -e "${Red}Invalid release asset name: ${asset_name}${ColorOff}" >&2
    exit 1
  fi

  release_tmpdir=$(mktemp -d)
  archive_path="$release_tmpdir/$asset_name"
  trap 'rm -rf "$release_tmpdir"' EXIT

  echo -e "${Green}Downloading release asset: ${asset_name}${ColorOff}"
  if ! curl -fL "$release_url" -o "$archive_path"; then
    echo -e "${Red}Failed to download ${release_url}${ColorOff}" >&2
    exit 1
  fi

  echo -e "${Green}Extracting release archive...${ColorOff}"
  tar -xzf "$archive_path" -C "$release_tmpdir"

  if [ ! -x "$release_tmpdir/anytls-server" ]; then
    echo -e "${Red}Expected binary not found in release archive: anytls-server${ColorOff}" >&2
    exit 1
  fi
  install -m 0755 "$release_tmpdir/anytls-server" "$BIN_DIR/anytls-server"
  echo -e "${Green}Installed anytls-server to $BIN_DIR${ColorOff}"
}

generate_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr '/+' '_-' | tr -d '='
  else
    check_command python3
    python3 - <<'PY'
import secrets
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
print(''.join(secrets.choice(alphabet) for _ in range(32)))
PY
  fi
}

generate_certificates() {
  check_command openssl

  local fake_domain="${1:?fake domain required}"

  mkdir -p "$INSTALL_DIR"

  echo -e "${Green}Generating certificates for ${fake_domain}${ColorOff}"
  openssl genrsa -out "$INSTALL_DIR/ca.key" 4096
  openssl req -x509 -new -nodes -key "$INSTALL_DIR/ca.key" -sha256 -days 3650 \
    -subj "/CN=AnyTLS Local CA" -out "$INSTALL_DIR/ca.crt"

  openssl genrsa -out "$INSTALL_DIR/server.key" 2048
  openssl req -new -key "$INSTALL_DIR/server.key" -subj "/CN=${fake_domain}" -out "$INSTALL_DIR/server.csr"

  cat > "$INSTALL_DIR/server.ext" <<EOF
[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = ${fake_domain}
EOF

  openssl x509 -req -in "$INSTALL_DIR/server.csr" -CA "$INSTALL_DIR/ca.crt" -CAkey "$INSTALL_DIR/ca.key" \
    -CAcreateserial -out "$INSTALL_DIR/server.crt" -days 3650 -sha256 -extfile "$INSTALL_DIR/server.ext" -extensions v3_req
  rm -f "$INSTALL_DIR/ca.srl" "$INSTALL_DIR/server.csr" "$INSTALL_DIR/server.ext"
}

install_systemd_service() {
  local fake_domain="$1"
  local listen_port="$2"
  local password="$3"
  local service_path="/etc/systemd/system/$SERVICE_UNIT_NAME"

  cat > "$service_path" <<EOF
[Unit]
Description=AnyTLS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/anytls-server -l 0.0.0.0:${listen_port} -p ${password} --sni ${fake_domain} --cert $INSTALL_DIR/server.crt --key $INSTALL_DIR/server.key
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable --now "$SERVICE_UNIT_NAME" || true
  fi
}

install_all() {
  local fake_domain="$1"
  local listen_port="$2"
  local password="${3:-}"
  local asset_name
  local server_addr

  if [ -z "$fake_domain" ] || [ -z "$listen_port" ]; then
    usage
    exit 1
  fi

  if [ -z "$password" ]; then
    password=$(generate_password)
  fi

  check_command install
  asset_name=$(detect_release_asset)
  mkdir -p "$BIN_DIR"
  download_release "$asset_name"
  generate_certificates "$fake_domain"
  install_systemd_service "$fake_domain" "$listen_port" "$password"
  server_addr=$(resolve_hostaddr)

  echo -e "${Green}Install complete.${ColorOff}"
  echo -e "${Yellow}Server command:${ColorOff} $BIN_DIR/anytls-server -l 0.0.0.0:${listen_port} -p ${password} --sni ${fake_domain} --cert ${INSTALL_DIR}/server.crt --key ${INSTALL_DIR}/server.key"
  echo -e "${Yellow}Root CA for client:${ColorOff} ${INSTALL_DIR}/ca.crt"
  echo -e "${Green}\n\n==== Root CA CERTIFICATE (${INSTALL_DIR}/ca.crt) ====\n\n${ColorOff}"
  cat "$INSTALL_DIR/ca.crt"
  echo -e "${Yellow}\n\nClient usage:${ColorOff} anytls-client -l 127.0.0.1:3080 -s ${server_addr}:${listen_port} -p ${password} --sni ${fake_domain} --root-cert ${INSTALL_DIR}/ca.crt\n\n"
}

uninstall_all() {
  echo -e "${Green}Uninstalling AnyTLS...${ColorOff}"

  if command -v systemctl >/dev/null 2>&1 && [ -f "/etc/systemd/system/$SERVICE_UNIT_NAME" ]; then
    systemctl stop "$SERVICE_UNIT_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_UNIT_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE_UNIT_NAME"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  rm -f "$BIN_DIR/anytls-server"
  rm -rf "$INSTALL_DIR"
  echo -e "${Green}Uninstall complete.${ColorOff}"
}

case "${1:-}" in
  install)
    require_root
    install_all "${2:-}" "${3:-}" "${4:-}"
    ;;
  uninstall)
    require_root
    uninstall_all
    ;;
  *)
    usage
    exit 1
    ;;
esac
