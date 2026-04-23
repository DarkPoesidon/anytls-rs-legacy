#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
password="password"
server_listen="127.0.0.1:18443"
client_listen="127.0.0.1:12080"
udp_echo_port=19090
artifacts_dir="$repo_root/target/uot-local-sh"
server_stdout="$artifacts_dir/server.stdout.log"
server_stderr="$artifacts_dir/server.stderr.log"
client_stdout="$artifacts_dir/client.stdout.log"
client_stderr="$artifacts_dir/client.stderr.log"

mkdir -p "$artifacts_dir"

cleanup() {
  local exit_code=$?
  if [[ -n "${client_pid:-}" ]] && kill -0 "$client_pid" 2>/dev/null; then
    kill "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  if [[ -n "${server_pid:-}" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "${udp_pid:-}" ]] && kill -0 "$udp_pid" 2>/dev/null; then
    kill "$udp_pid" 2>/dev/null || true
    wait "$udp_pid" 2>/dev/null || true
  fi
  exit "$exit_code"
}
trap cleanup EXIT

echo "Starting local UDP echo server on 127.0.0.1:${udp_echo_port}"
python3 -u - <<'PY' "$udp_echo_port" &
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", port))
try:
    while True:
        data, addr = sock.recvfrom(65535)
        sock.sendto(data, addr)
finally:
    sock.close()
PY
udp_pid=$!

echo "Starting anytls-server on ${server_listen}"
(cd "$repo_root" && cargo run --bin anytls-server -- -l "$server_listen" -p "$password") >"$server_stdout" 2>"$server_stderr" &
server_pid=$!

echo "Starting anytls-client on ${client_listen}"
(cd "$repo_root" && cargo run --bin anytls-client -- -l "$client_listen" -s "$server_listen" -p "$password") >"$client_stdout" 2>"$client_stderr" &
client_pid=$!

python3 - <<'PY' "$client_listen" "$udp_echo_port"
import socket
import struct
import sys
import time

client_host, client_port = sys.argv[1].split(":", 1)
client_port = int(client_port)
udp_echo_port = int(sys.argv[2])

def wait_tcp_ready(host: str, port: int, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"Timed out waiting for TCP endpoint {host}:{port}")

def read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError(f"Unexpected EOF while reading {size} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def read_socks5_address(atyp: int, sock: socket.socket):
    if atyp == 1:
        addr = socket.inet_ntoa(read_exact(sock, 4))
    elif atyp == 4:
        addr = socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
    elif atyp == 3:
        size = read_exact(sock, 1)[0]
        addr = read_exact(sock, size).decode("ascii")
    else:
        raise RuntimeError(f"Unsupported SOCKS5 ATYP {atyp}")
    port = int.from_bytes(read_exact(sock, 2), "big")
    return addr, port

wait_tcp_ready("127.0.0.1", 18443)
wait_tcp_ready(client_host, client_port)

print("Opening SOCKS5 control connection")
with socket.create_connection((client_host, client_port), timeout=5.0) as control:
    control.sendall(b"\x05\x01\x00")
    auth_reply = read_exact(control, 2)
    if auth_reply != b"\x05\x00":
        raise RuntimeError(f"SOCKS5 auth negotiation failed: {auth_reply.hex('-')}")

    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply_head = read_exact(control, 4)
    if reply_head[:2] != b"\x05\x00":
        raise RuntimeError(f"UDP ASSOCIATE failed: {reply_head.hex('-')}")

    relay_host, relay_port = read_socks5_address(reply_head[3], control)
    print(f"UDP ASSOCIATE raw response: {reply_head.hex('-')}")
    print(f"SOCKS5 UDP relay is listening on {relay_host}:{relay_port}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
        udp_sock.settimeout(5.0)
        payload = b"anytls-uot-ok"
        packet = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_echo_port) + payload
        udp_sock.sendto(packet, (relay_host, relay_port))
        response, _ = udp_sock.recvfrom(65535)

    if response[:3] != b"\x00\x00\x00":
        raise RuntimeError(f"Unexpected SOCKS5 UDP header: {response[:3].hex('-')}")
    if response[3] != 1:
        raise RuntimeError(f"Unexpected UDP address type {response[3]}")

    source_ip = socket.inet_ntoa(response[4:8])
    source_port = int.from_bytes(response[8:10], "big")
    response_payload = response[10:]

    if response_payload != payload:
        raise RuntimeError(f"Unexpected UDP payload: {response_payload!r}")
    if source_ip != "127.0.0.1" or source_port != udp_echo_port:
        raise RuntimeError(f"Unexpected UDP source {source_ip}:{source_port}")

print("UDP ASSOCIATE end-to-end validation passed")
PY