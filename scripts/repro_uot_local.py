#!/usr/bin/env python3
"""
Run a local reproduction for UDP-over-TCP (UOT) using anytls-server and anytls-client.
Equivalent to scripts/repro_uot_local.sh but implemented in Python and cross-platform.
"""
import os
import sys
import time
import socket
import struct
import threading
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
ARTIFACTS = ROOT / 'target' / 'uot-local-py'
ARTIFACTS.mkdir(parents=True, exist_ok=True)

# Defaults from the original shell script
PASSWORD = 'password'
SERVER_LISTEN = '127.0.0.1:18443'
CLIENT_LISTEN = '127.0.0.1:12080'
UDP_ECHO_PORT = 19090

DEBUG_DIR = ROOT / 'target' / 'debug'
SERVER_BINARY = DEBUG_DIR / 'anytls-server'
CLIENT_BINARY = DEBUG_DIR / 'anytls-client'
if (SERVER_BINARY.with_suffix('.exe')).exists():
    SERVER_BINARY = SERVER_BINARY.with_suffix('.exe')
if (CLIENT_BINARY.with_suffix('.exe')).exists():
    CLIENT_BINARY = CLIENT_BINARY.with_suffix('.exe')

SERVER_STDOUT = ARTIFACTS / 'server.stdout.log'
SERVER_STDERR = ARTIFACTS / 'server.stderr.log'
CLIENT_STDOUT = ARTIFACTS / 'client.stdout.log'
CLIENT_STDERR = ARTIFACTS / 'client.stderr.log'

# import helpers
sys.path.insert(0, str(ROOT))
from scripts.utils import start_proc, terminate_proc, wait_for_port

udp_thread = None
udp_stop = threading.Event()


def udp_echo_server(bind_host: str, bind_port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_host, bind_port))
    try:
        while not udp_stop.is_set():
            try:
                sock.settimeout(0.5)
                data, addr = sock.recvfrom(65535)
                sock.sendto(data, addr)
            except socket.timeout:
                continue
    finally:
        sock.close()


def request_termination(proc, name='process'):
    try:
        terminate_proc(proc, name=name)
    except Exception:
        pass


def main():
    if not SERVER_BINARY.exists() or not os.access(str(SERVER_BINARY), os.X_OK):
        print(f"Server binary not found at {SERVER_BINARY}. Build it first: cargo build --bin anytls-server", file=sys.stderr)
        return 2
    if not CLIENT_BINARY.exists() or not os.access(str(CLIENT_BINARY), os.X_OK):
        print(f"Client binary not found at {CLIENT_BINARY}. Build it first: cargo build --bin anytls-client", file=sys.stderr)
        return 2

    # Start local UDP echo server in a background thread
    bind_host = '127.0.0.1'
    bind_port = UDP_ECHO_PORT
    print(f"Starting local UDP echo server on {bind_host}:{bind_port}")
    global udp_thread
    udp_thread = threading.Thread(target=udp_echo_server, args=(bind_host, bind_port), daemon=True)
    udp_thread.start()

    # Start anytls-server
    print(f"Starting anytls-server on {SERVER_LISTEN} from {SERVER_BINARY}")
    srv_cmd = [str(SERVER_BINARY), '-l', SERVER_LISTEN, '-p', PASSWORD]
    srv_proc, srv_f = start_proc(srv_cmd, stdout_path=str(SERVER_STDOUT))

    # Start anytls-client
    print(f"Starting anytls-client on {CLIENT_LISTEN} from {CLIENT_BINARY}")
    cl_cmd = [str(CLIENT_BINARY), '-l', CLIENT_LISTEN, '-s', SERVER_LISTEN, '-p', PASSWORD]
    cl_proc, cl_f = start_proc(cl_cmd, stdout_path=str(CLIENT_STDOUT))

    # Wait for server and client to be ready
    host_s, port_s = SERVER_LISTEN.split(':', 1)
    port_s = int(port_s)
    client_host, client_port = CLIENT_LISTEN.split(':', 1)
    client_port = int(client_port)

    try:
        if not wait_for_port(host_s, port_s, timeout=10.0):
            print('Server did not become ready in time', file=sys.stderr)
            return 3
        if not wait_for_port(client_host, client_port, timeout=10.0):
            print('Client did not become ready in time', file=sys.stderr)
            return 4

        print('Opening SOCKS5 control connection')
        # connect to client's SOCKS5 control port
        with socket.create_connection((client_host, client_port), timeout=5.0) as control:
            control.sendall(b"\x05\x01\x00")
            auth_reply = control.recv(2)
            if auth_reply != b"\x05\x00":
                raise RuntimeError(f"SOCKS5 auth negotiation failed: {auth_reply!r}")

            # UDP ASSOCIATE: VER=5, CMD=3, RSV=0, ATYP=1 (IPv4) + 4 bytes addr + 2 bytes port (0.0.0.0:0 to let server pick)
            control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            reply_head = control.recv(4)
            if len(reply_head) < 4 or reply_head[:2] != b"\x05\x00":
                raise RuntimeError(f"UDP ASSOCIATE failed: {reply_head!r}")

            # read address according to ATYP
            atyp = reply_head[3]
            def read_exact(sock, n):
                buf = b''
                while len(buf) < n:
                    chunk = sock.recv(n - len(buf))
                    if not chunk:
                        raise RuntimeError('unexpected EOF')
                    buf += chunk
                return buf

            if atyp == 1:
                addr = socket.inet_ntoa(read_exact(control, 4))
            elif atyp == 3:
                size = read_exact(control, 1)[0]
                addr = read_exact(control, size).decode('ascii')
            elif atyp == 4:
                addr = socket.inet_ntop(socket.AF_INET6, read_exact(control, 16))
            else:
                raise RuntimeError(f'Unsupported ATYP {atyp}')
            port_bytes = read_exact(control, 2)
            relay_port = int.from_bytes(port_bytes, 'big')
            relay_host = addr

            print(f'SOCKS5 UDP relay at {relay_host}:{relay_port}')

            # send a UDP packet via the relay to the local UDP echo server
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(5.0)
            payload = b'anytls-uot-ok'
            # SOCKS5 UDP request header: RSV(2)=0, FRAG=0, ATYP=1, DST.ADDR (4), DST.PORT (2)
            packet = b"\x00\x00\x00\x01" + socket.inet_aton('127.0.0.1') + struct.pack('!H', UDP_ECHO_PORT) + payload
            udp_sock.sendto(packet, (relay_host, relay_port))
            response, _ = udp_sock.recvfrom(65535)
            udp_sock.close()

            if response[:3] != b"\x00\x00\x00":
                raise RuntimeError(f'Unexpected SOCKS5 UDP header: {response[:3]!r}')
            if response[3] != 1:
                raise RuntimeError(f'Unexpected UDP address type {response[3]}')
            source_ip = socket.inet_ntoa(response[4:8])
            source_port = int.from_bytes(response[8:10], 'big')
            response_payload = response[10:]

            if response_payload != payload:
                raise RuntimeError(f'Unexpected UDP payload: {response_payload!r}')
            if source_ip != '127.0.0.1' or source_port != UDP_ECHO_PORT:
                raise RuntimeError(f'Unexpected UDP source {source_ip}:{source_port}')

        print('UDP ASSOCIATE end-to-end validation passed')
        return 0
    except Exception as e:
        print('Test failed:', e, file=sys.stderr)
        return 5
    finally:
        print('Cleaning up')
        udp_stop.set()
        if udp_thread:
            udp_thread.join(timeout=1.0)
        request_procs = []
        try:
            request_procs.append((cl_proc, CLIENT_BINARY.name))
        except NameError:
            pass
        try:
            request_procs.append((srv_proc, SERVER_BINARY.name))
        except NameError:
            pass
        for p, name in request_procs:
            request_termination = terminate_proc
            try:
                request_termination(p, name=name)
            except Exception:
                pass


if __name__ == '__main__':
    sys.exit(main())
