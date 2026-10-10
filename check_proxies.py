"""
check_proxies.py
----------------
Reads a raw proxy list, tests each one against a real HTTP endpoint,
and writes only the working proxies to an output file.

Accepts string or Path arguments throughout, so it can be imported and
called by other scripts (e.g. loop.py) with plain string paths.

Usage:
    python check_proxies.py                       # uses defaults below
    python check_proxies.py -i raw.txt -o out.txt -t 8 -w 64
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import socket
import ssl
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# CONFIG (defaults — overridable from the command line)
# ---------------------------------------------------------------------------
INPUT_FILE = "free-proxy-list.txt"
OUTPUT_FILE = "working-proxies.txt"
TEST_URL_HOST = "api.ipify.org"
TEST_URL_PATH = "/?format=json"
TEST_PORT = 80
DEFAULT_TIMEOUT = 8.0
DEFAULT_WORKERS = 64
BASE_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# DATA MODEL
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProxyConfig:
    raw: str
    scheme: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None


# ---------------------------------------------------------------------------
# PARSING
# ---------------------------------------------------------------------------
def load_lines(path) -> list[str]:
    """Load non-empty, non-comment lines. Accepts str or Path."""
    path = Path(path)
    if not path.exists():
        return []
    lines: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def parse_proxy(line: str) -> Optional[ProxyConfig]:
    """Auto-detect: host:port | host:port:user:pass | user:pass@host:port | scheme://..."""
    raw = line.strip()
    if not raw:
        return None

    scheme = "http"
    remainder = raw
    if "://" in remainder:
        scheme, remainder = remainder.split("://", 1)
        scheme = scheme.lower()

    username = password = None

    if "@" in remainder:
        creds, remainder = remainder.rsplit("@", 1)
        if ":" in creds:
            username, password = creds.split(":", 1)
        else:
            username = creds

    parts = remainder.split(":")
    if len(parts) == 2:
        host, port_text = parts
    elif len(parts) == 4:
        host, port_text, username, password = parts
    else:
        return None

    try:
        port = int(port_text)
    except ValueError:
        return None
    if not host:
        return None

    return ProxyConfig(raw=raw, scheme=scheme, host=host, port=port,
                       username=username, password=password)


# ---------------------------------------------------------------------------
# LOW-LEVEL HTTP HELPERS
# ---------------------------------------------------------------------------
def build_http_request(proxy: ProxyConfig, path: str, origin_form: bool,
                       include_proxy_auth: bool) -> bytes:
    target = f"http://{TEST_URL_HOST}{path}" if origin_form else path
    headers = [
        f"GET {target} HTTP/1.1",
        f"Host: {TEST_URL_HOST}",
        "Connection: close",
        "User-Agent: ProxyChecker/1.0",
        "Accept: */*",
    ]
    if include_proxy_auth and proxy.username is not None:
        creds = f"{proxy.username}:{proxy.password or ''}".encode("utf-8")
        headers.append(f"Proxy-Authorization: Basic {base64.b64encode(creds).decode('ascii')}")
    headers += ["", ""]
    return "\r\n".join(headers).encode("ascii")


def recv_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    data = bytearray()
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) != size:
        raise OSError("Unexpected end of proxy response")
    return bytes(data)


def read_http_status(sock: socket.socket) -> Optional[int]:
    data = recv_until(sock, b"\r\n\r\n")
    if not data:
        return None
    head = data.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="ignore")
    parts = head.split()
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    return int(parts[1])


def connect_socket(proxy: ProxyConfig, timeout: float) -> socket.socket:
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    sock.settimeout(timeout)
    if proxy.scheme == "https":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=proxy.host)
        sock.settimeout(timeout)
    return sock


# ---------------------------------------------------------------------------
# PROTOCOL CHECKS
# ---------------------------------------------------------------------------
def check_http_proxy(proxy: ProxyConfig, timeout: float) -> bool:
    sock = connect_socket(proxy, timeout)
    try:
        sock.sendall(build_http_request(proxy, TEST_URL_PATH, True, True))
        status = read_http_status(sock)
        return status is not None and 200 <= status < 400
    finally:
        sock.close()


def socks4_connect(sock: socket.socket, proxy: ProxyConfig) -> None:
    try:
        ip_bytes = socket.inet_aton(TEST_URL_HOST)
        domain = None
    except OSError:
        ip_bytes, domain = b"\x00\x00\x00\x01", TEST_URL_HOST.encode("idna")

    packet = bytearray(b"\x04\x01")
    packet.extend(struct.pack(">H", TEST_PORT))
    packet.extend(ip_bytes)
    packet.extend((proxy.username or "").encode("utf-8"))
    packet.append(0)
    if domain is not None:
        packet.extend(domain)
        packet.append(0)

    sock.sendall(bytes(packet))
    if recv_exact(sock, 8)[1] != 0x5A:
        raise OSError("SOCKS4 connect rejected")


def socks5_connect(sock: socket.socket, proxy: ProxyConfig) -> None:
    methods = [0x00]
    if proxy.username is not None:
        methods.append(0x02)
    sock.sendall(bytes([0x05, len(methods), *methods]))
    response = recv_exact(sock, 2)
    if response[0] != 0x05:
        raise OSError("Invalid SOCKS5 handshake")

    method = response[1]
    if method == 0xFF:
        raise OSError("SOCKS5 no acceptable auth methods")
    if method == 0x02:
        u = (proxy.username or "").encode("utf-8")
        p = (proxy.password or "").encode("utf-8")
        sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        if recv_exact(sock, 2)[1] != 0x00:
            raise OSError("SOCKS5 authentication failed")

    host_bytes = TEST_URL_HOST.encode("idna")
    req = bytearray(b"\x05\x01\x00\x03")
    req.append(len(host_bytes))
    req.extend(host_bytes)
    req.extend(struct.pack(">H", TEST_PORT))
    sock.sendall(bytes(req))

    resp = recv_exact(sock, 4)
    if resp[1] != 0x00:
        raise OSError("SOCKS5 connect rejected")

    atyp = resp[3]
    if atyp == 0x01:
        recv_exact(sock, 4)
    elif atyp == 0x03:
        recv_exact(sock, recv_exact(sock, 1)[0])
    elif atyp == 0x04:
        recv_exact(sock, 16)
    recv_exact(sock, 2)


def check_socks_proxy(proxy: ProxyConfig, timeout: float) -> bool:
    sock = connect_socket(proxy, timeout)
    try:
        if proxy.scheme == "socks4":
            socks4_connect(sock, proxy)
        elif proxy.scheme == "socks5":
            socks5_connect(sock, proxy)
        else:
            raise OSError(f"Unsupported proxy scheme: {proxy.scheme}")
        sock.sendall(build_http_request(proxy, TEST_URL_PATH, False, False))
        status = read_http_status(sock)
        return status is not None and 200 <= status < 400
    finally:
        sock.close()


def check_proxy(proxy: ProxyConfig, timeout: float) -> tuple[ProxyConfig, bool, str]:
    try:
        if proxy.scheme in {"http", "https"}:
            return proxy, check_http_proxy(proxy, timeout), ""
        if proxy.scheme in {"socks4", "socks5"}:
            return proxy, check_socks_proxy(proxy, timeout), ""
        return proxy, False, f"unsupported scheme: {proxy.scheme}"
    except Exception as exc:
        return proxy, False, str(exc)


# ---------------------------------------------------------------------------
# ORCHESTRATION
# ---------------------------------------------------------------------------
def write_lines(path, lines: Iterable[str]) -> None:
    """Write lines to a file. Accepts str or Path."""
    path = Path(path)
    content = "\n".join(lines)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")


def run(input_file, output_file, timeout: float, workers: int) -> int:
    """Check every proxy in input_file; write working ones to output_file."""
    input_file = Path(input_file)
    output_file = Path(output_file)

    raw_lines = load_lines(input_file)
    proxies = [p for line in raw_lines if (p := parse_proxy(line)) is not None]

    if not proxies:
        print(f"No proxies found in {input_file}")
        write_lines(output_file, [])
        return 1

    workers = max(1, min(workers, len(proxies)))
    print(f"Loaded {len(proxies)} proxies from {input_file}")
    print(f"Checking with {workers} worker(s) and {timeout:.1f}s timeout")

    working: list[str] = []
    checked = 0
    with futures.ThreadPoolExecutor(max_workers=workers) as executor:
        fmap = {executor.submit(check_proxy, p, timeout): p for p in proxies}
        for fut in futures.as_completed(fmap):
            proxy, ok, error = fut.result()
            checked += 1
            status = "WORKING" if ok else "dead"
            suffix = f" ({error})" if (not ok and error) else ""
            print(f"[{checked}/{len(proxies)}] {status}: {proxy.raw}{suffix}")
            if ok:
                working.append(proxy.raw)

    write_lines(output_file, working)
    print(f"Saved {len(working)} working proxies to {output_file}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Check proxies and save the working ones.")
    p.add_argument("-i", "--input", default=INPUT_FILE)
    p.add_argument("-o", "--output", default=OUTPUT_FILE)
    p.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    inp = Path(args.input)
    out = Path(args.output)
    if not inp.is_absolute():
        inp = BASE_DIR / inp
    if not out.is_absolute():
        out = BASE_DIR / out
    return run(inp, out, args.timeout, args.workers)


if __name__ == "__main__":
    raise SystemExit(main())