#!/usr/bin/env python3
import os
import sys
import subprocess
import signal
import time
import socket
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CERT = SCRIPTS / "selfsigned.crt"
#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CERT = SCRIPTS / "selfsigned.crt"
KEY = SCRIPTS / "selfsigned.key"
SERVER_LOG = SCRIPTS / "server.log"
S_CLIENT_OUT = SCRIPTS / "s_client.out"
INTEGRATION_OUT = SCRIPTS / "integration_client.out"

# ensure repo root is on sys.path so `scripts` package is importable when running this file
sys.path.insert(0, str(ROOT))

# import helpers from scripts.utils
from scripts.utils import (
    find_free_port,
    wait_for_port,
    start_proc,
    terminate_proc,
    ensure_cert,
)


def run(cmd, **kwargs):
    return subprocess.run(cmd, shell=False, check=False, **kwargs)


def main():
    os.chdir(ROOT)
    ok = ensure_cert()
    if not ok:
        print("Certificate not available; aborting")
        sys.exit(1)

    port = find_free_port()
    print(f"Using TLS port {port}")

    print("Building anytls-server and anytls-client")
    run([shutil.which('cargo') or 'cargo', 'build', '--bin', 'anytls-server'])
    run([shutil.which('cargo') or 'cargo', 'build', '--bin', 'anytls-client'])

    bin_server = ROOT / 'target' / 'debug' / 'anytls-server'
    if (bin_server.with_suffix('.exe')).exists():
        bin_server = bin_server.with_suffix('.exe')
    bin_client = ROOT / 'target' / 'debug' / 'anytls-client'
    if (bin_client.with_suffix('.exe')).exists():
        bin_client = bin_client.with_suffix('.exe')

    print(f"Starting anytls-server: {bin_server}")
    srv_proc, srv_f = start_proc([str(bin_server), '--password', 'testpass', '--cert', str(CERT), '--key', str(KEY), '--listen', f'127.0.0.1:{port}', '--log', 'info'], stdout_path=str(SERVER_LOG))
    time.sleep(1)

    print("Running openssl s_client handshake check")
    if shutil.which('openssl'):
        # Use Popen with stdin=DEVNULL and a short timeout to avoid blocking
        with open(S_CLIENT_OUT, 'wb') as f:
            proc = subprocess.Popen(['openssl', 's_client', '-connect', f'127.0.0.1:{port}', '-servername', 'localhost', '-quiet'], stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                terminate_proc(proc, name='openssl.exe' if os.name=='nt' else 'openssl')
        try:
            print(Path(S_CLIENT_OUT).read_text()[:10240])
        except Exception:
            pass
    else:
        print("openssl not found; skipping s_client check")

    print("== Full integration test: anytls-client <-> anytls-server with local HTTP backend ==")
    http_port = find_free_port()
    socks_port = find_free_port()
    print(f"HTTP {http_port}, SOCKS {socks_port}")

    www_dir = SCRIPTS / 'integration-www'
    www_dir.mkdir(parents=True, exist_ok=True)
    (www_dir / 'index.html').write_text('hello-from-backend')

    print(f"Starting local HTTP server on 127.0.0.1:{http_port}")
    http_proc, _ = start_proc([sys.executable, '-m', 'http.server', str(http_port), '--bind', '127.0.0.1', '--directory', str(www_dir)])
    time.sleep(0.5)

    if not wait_for_port('127.0.0.1', port, timeout=3.0):
        print('Server did not start in time; dumping server log')
        if SERVER_LOG.exists():
            print(SERVER_LOG.read_text())
        terminate_proc(srv_proc, name=bin_server.name)
        terminate_proc(http_proc, name='python.exe' if os.name=='nt' else 'python')
        sys.exit(1)

    print(f"Starting anytls-server on localhost (integration instance): {bin_server}")
    srv2_proc, srv2_f = start_proc([str(bin_server), '--password', 'testpass', '--cert', str(CERT), '--key', str(KEY), '--listen', f'127.0.0.1:{port}', '--log', 'info'], stdout_path=str(SERVER_LOG))
    time.sleep(1)

    print(f"Starting anytls-client pointing to server, exposing SOCKS5 on 127.0.0.1:{socks_port}")
    cl_proc, cl_f = start_proc([str(bin_client), '--server', f'127.0.0.1:{port}', '--password', 'testpass', '--listen', f'127.0.0.1:{socks_port}', '--log', 'info'])
    time.sleep(2)

    print("Testing HTTP fetch via SOCKS5 proxy")
    used = False
    if shutil.which('curl'):
        run(['curl', '--socks5', f'127.0.0.1:{socks_port}', '-sS', f'http://127.0.0.1:{http_port}/'], stdout=open(INTEGRATION_OUT, 'wb'))
        used = True
    if not used:
        print('curl not found or not used; please run the integration fetch manually via socks proxy')
    else:
        out = Path(INTEGRATION_OUT).read_text()
        print(out)

    success = 'hello-from-backend' in (Path(INTEGRATION_OUT).read_text() if Path(INTEGRATION_OUT).exists() else '')

    if success:
        print('Integration test passed: fetched content via proxy')
        status = 0
    else:
        print('Integration test failed: backend content not fetched')
        if SERVER_LOG.exists():
            print('Server log (tail):')
            print('\n'.join(SERVER_LOG.read_text().splitlines()[-200:]))
        status = 1

    print('Cleaning up processes')
    for p, name in [(cl_proc, bin_client.name), (srv2_proc, bin_server.name), (http_proc, 'python.exe' if os.name=='nt' else 'python'), (srv_proc, bin_server.name)]:
        try:
            terminate_proc(p, name=name)
        except Exception:
            pass

    for fh in (srv_f, srv2_f, cl_f) if 'srv_f' in locals() else []:
        try:
            fh and fh.close()
        except Exception:
            pass

    sys.exit(status)


if __name__ == '__main__':
    main()
    used = False
