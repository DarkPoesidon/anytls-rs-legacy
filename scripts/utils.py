"""Utility helpers for smoke/integration scripts.
Provides: find_free_port, wait_for_port, start_proc, terminate_proc, ensure_cert
"""
from pathlib import Path
import socket
import time
import os
import subprocess
import sys
import shutil
import signal

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
CERT = SCRIPTS / "selfsigned.crt"
KEY = SCRIPTS / "selfsigned.key"


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_port(host, port, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.1)
    return False


def start_proc(cmd, stdout_path=None, detach=True):
    f = None
    if stdout_path:
        f = open(stdout_path, "ab")

    kwargs = {}
    if os.name == 'nt':
        try:
            creation = subprocess.CREATE_NEW_PROCESS_GROUP
        except AttributeError:
            creation = 0x00000200
        DETACHED = 0x00000008
        if detach:
            kwargs['creationflags'] = creation | DETACHED
    else:
        if detach:
            kwargs['start_new_session'] = True

    proc = subprocess.Popen(cmd, stdout=f or subprocess.DEVNULL, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kwargs)
    return proc, f


def terminate_proc(proc, name=None, timeout=2.0):
    if not proc:
        return
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
    if os.name == 'nt':
        try:
            if name and shutil.which('taskkill'):
                subprocess.run(["taskkill", "/IM", name, "/F"], check=False)
            elif shutil.which('taskkill'):
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], check=False)
        except Exception:
            pass
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass


def ensure_cert():
    if CERT.exists() and KEY.exists():
        return True
    genpy = SCRIPTS / "gen_cert.py"
    if genpy.exists() and shutil.which(sys.executable):
        subprocess.run([sys.executable, str(genpy)])
        return CERT.exists() and KEY.exists()
    if shutil.which('openssl'):
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-sha256", "-days", "3650", "-subj", "/CN=localhost",
            "-keyout", str(KEY), "-out", str(CERT)
        ]
        subprocess.run(cmd)
        return CERT.exists() and KEY.exists()
    return False
