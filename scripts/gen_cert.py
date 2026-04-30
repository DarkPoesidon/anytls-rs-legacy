#!/usr/bin/env python3
"""
Generate a 10-year self-signed certificate and private key (RSA 2048).
Writes `selfsigned.crt` and `selfsigned.key` into the scripts/ directory.
Requires OpenSSL available on PATH.
"""
import subprocess
import shutil
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent
CRT = SCRIPTS / "selfsigned.crt"
KEY = SCRIPTS / "selfsigned.key"

def main():
    if CRT.exists() and KEY.exists():
        print("Certificate + key already exist:", CRT, KEY)
        return 0
    if not shutil.which('openssl'):
        print('openssl not found; please install OpenSSL or create certs manually', file=sys.stderr)
        return 2
    cmd = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-sha256', '-days', '3650', '-subj', '/CN=localhost',
        '-keyout', str(KEY), '-out', str(CRT)
    ]
    print('Running:', ' '.join(cmd))
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print('openssl failed', file=sys.stderr)
        return res.returncode
    print('Wrote:', CRT, KEY)
    return 0

if __name__ == '__main__':
    sys.exit(main())
