"""
geo_resolve.py
--------------
Resolves the exit country and ISP details of every proxy in working-proxies.txt,
identifies datacenter vs. consumer IPs, and writes proxy-geo.json.
"""
import json
import socket
from pathlib import Path
import httpx
from check_proxies import load_lines, parse_proxy

IN_FILE  = "working-proxies.txt"
OUT_FILE = "proxy-geo.json"
BATCH    = 100

HOSTING_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh",
    "hetzner", "linode", "vultr", "contabo", "oracle", "alibaba", "tencent",
    "cloudflare", "m247", "datacamp", "leaseweb", "colocrossing", "choopa",
    "server", "hosting", "datacenter", "vps",
)

def is_datacenter(isp: str, org: str, asn: str) -> bool:
    blob = f"{isp} {org} {asn}".lower()
    return any(k in blob for k in HOSTING_KEYWORDS)

def _ip_for(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None

def resolve(ip_to_keys: dict[str, list[str]]) -> dict[str, dict]:
    out = {}
    ips = list(ip_to_keys.keys())
    with httpx.Client(timeout=20.0) as c:
        for i in range(0, len(ips), BATCH):
            chunk = ips[i:i + BATCH]
            payload = [{"query": ip, "fields": "countryCode,isp,org,as,query"} for ip in chunk]
            try:
                r = c.post("http://ip-api.com/batch", json=payload)
                for item in r.json():
                    if item.get("countryCode"):
                        ip_query = item["query"]
                        cc = item["countryCode"]
                        isp = item.get("isp", "")
                        org = item.get("org", "")
                        asn = item.get("as", "")
                        datacenter = is_datacenter(isp, org, asn)
                        out[ip_query] = {
                            "country": cc,
                            "is_datacenter": datacenter
                        }
            except Exception as e:
                print(f"[-] geo batch failed: {e}")
    return out

def main() -> None:
    ip_to_keys: dict[str, list[str]] = {}
    for line in load_lines(IN_FILE):
        cfg = parse_proxy(line)
        if not cfg:
            continue
        ip = _ip_for(cfg.host)
        if ip:
            ip_to_keys.setdefault(ip, []).append(f"{cfg.scheme}://{cfg.host}:{cfg.port}")

    ip_info = resolve(ip_to_keys)
    mapping = {}
    
    for ip, keys in ip_to_keys.items():
        info = ip_info.get(ip)
        if info:
            for k in keys:
                mapping[k] = {
                    "country": info["country"],
                    "is_datacenter": info["is_datacenter"]
                }

    Path(OUT_FILE).write_text(json.dumps(mapping, indent=2), encoding="utf-8")
    print(f"[+] Wrote {OUT_FILE} with {len(mapping)} mapped proxies (including ISP classifier)")

if __name__ == "__main__":
    main()