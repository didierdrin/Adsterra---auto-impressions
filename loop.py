"""
loop.py
-------
Opens N tabs per cycle through random working proxies, dwells, clicks, closes.
Reports how many tabs ACTUALLY loaded, how fast, and why the rest failed.
Sanitizes URLs (BOM / zero-width chars) so goto() never gets an invalid string.

Usage:
    python loop.py
"""

import random
import re
import time

from playwright.sync_api import sync_playwright

from check_proxies import load_lines, parse_proxy, run as run_proxy_check

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
BATCH_SIZE   = 100
DWELL        = 20
CLICK        = True
CYCLES       = 0          # 0 = run forever
PAUSE        = 10
LOAD_TIMEOUT = 10000      # ms
HEADLESS     = True

URL_FILE       = "urls.txt"
PROXY_FILE     = "working-proxies.txt"
RAW_PROXY_FILE = "free-proxy-list.txt"

# Proxy hygiene
RECHECK_EVERY = 1         # re-validate proxies every N cycles (0 = never)
REFRESH_MODE  = "recheck" # "recheck" = re-test working list; "full" = re-scan raw list
CHECK_TIMEOUT = 8.0
CHECK_WORKERS = 64

# ---------------------------------------------------------------------------
# IDENTITIES
# ---------------------------------------------------------------------------
PROFILES = [
    ("en-US", "America/New_York"),
    ("en-US", "America/Chicago"),
    ("en-US", "America/Los_Angeles"),
    ("en-US", "America/Phoenix"),
    ("en-GB", "Europe/London"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

VIEWPORTS = [(1366, 768), (1440, 900), (1536, 864), (1920, 1080), (1280, 720)]

STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = { runtime: {} };
Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
"""

CANVAS_JS = """
(() => {
  const seed = %d;
  const getImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (...args) {
    const d = getImageData.apply(this, args);
    for (let i = 0; i < d.data.length; i += 4) {
      d.data[i] = (d.data[i] + (seed & 3)) & 0xff;
    }
    return d;
  };
})();
"""

# ---------------------------------------------------------------------------
# URL SANITIZING
# BOM, zero-width, non-breaking space, bidi marks, etc.
# ---------------------------------------------------------------------------
_INVISIBLE = dict.fromkeys(map(ord, "\ufeff\u200b\u200c\u200d\u00a0\u200e\u200f"))


def clean_url(u: str) -> str:
    """Strip invisible chars/whitespace and ensure a scheme. Returns '' if unusable."""
    u = u.translate(_INVISIBLE).strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")


# ---------------------------------------------------------------------------
# PROXY HANDLING
# ---------------------------------------------------------------------------
def load_proxies() -> list[dict]:
    out = []
    for line in load_lines(PROXY_FILE):
        cfg = parse_proxy(line)
        if not cfg:
            continue
        proxy = {"server": f"{cfg.scheme}://{cfg.host}:{cfg.port}"}
        if cfg.username:
            proxy["username"] = cfg.username
            proxy["password"] = cfg.password or ""
        out.append(proxy)
    return out


def refresh_proxies() -> None:
    if REFRESH_MODE == "full":
        run_proxy_check(RAW_PROXY_FILE, PROXY_FILE, CHECK_TIMEOUT, CHECK_WORKERS)
    else:
        run_proxy_check(PROXY_FILE, PROXY_FILE, CHECK_TIMEOUT, CHECK_WORKERS)


# ---------------------------------------------------------------------------
# ACTIONS
# ---------------------------------------------------------------------------
def click_ad(page) -> None:
    """Prefer an off-domain / new-tab anchor (likely the ad), else fall back."""
    try:
        for fr in page.frames:
            try:
                anchors = fr.query_selector_all("a[href^='http']")
            except Exception:
                continue
            for el in anchors:
                try:
                    target = el.get_attribute("target") or ""
                    href = el.get_attribute("href") or ""
                    if target == "_blank" or "adsterra" in href or "auctionr" in href:
                        el.click(timeout=2000)
                        return
                except Exception:
                    pass
            if anchors:
                try:
                    anchors[0].click(timeout=2000)
                    return
                except Exception:
                    pass
    except Exception:
        pass
    try:
        page.mouse.click(400, 400)
    except Exception:
        pass


def build_context(browser, proxy):
    """Create one hardened context with a coherent identity."""
    w, h = random.choice(VIEWPORTS)
    locale, timezone = random.choice(PROFILES)
    ctx = browser.new_context(
        proxy=proxy,
        user_agent=random.choice(USER_AGENTS),
        viewport={"width": w, "height": h},
        locale=locale,
        timezone_id=timezone,
        color_scheme="light",
    )
    ctx.add_init_script(STEALTH_JS)
    ctx.add_init_script(CANVAS_JS % random.randint(0, 255))
    return ctx


def run_cycle(browser, urls, proxies):
    """Returns (loaded, avg_load_s, fail_counts, samples)."""
    contexts, pages = [], []

    # De-dupe proxies within the batch so no IP is reused in one cycle.
    if proxies:
        pool = random.sample(proxies, min(BATCH_SIZE, len(proxies)))
        while len(pool) < BATCH_SIZE:
            pool.append(random.choice(proxies))
    else:
        pool = [None] * BATCH_SIZE

    loaded = 0
    total_load_time = 0.0
    fails: dict[str, int] = {}
    samples: list[str] = []

    for i in range(BATCH_SIZE):
        proxy = pool[i] if i < len(pool) else (random.choice(proxies) if proxies else None)
        ctx = build_context(browser, proxy)
        pg = ctx.new_page()
        url = random.choice(urls)

        t1 = time.time()
        try:
            #resp = pg.goto(url, wait_until="domcontentloaded", timeout=LOAD_TIMEOUT)
            resp = pg.goto(url, wait_until="commit", timeout=LOAD_TIMEOUT)
            total_load_time += time.time() - t1
            status = resp.status if resp else 0
            if status and status < 400:
                loaded += 1
                if len(samples) < 3:
                    samples.append(f"{status} {pg.url[:70]}")
            else:
                key = f"http {status}"
                fails[key] = fails.get(key, 0) + 1
        except Exception as e:
            total_load_time += time.time() - t1
            msg = str(e)
            m = re.search(r"net::ERR_[A-Z_]+", msg)
            key = m.group(0) if m else f"{type(e).__name__}: {msg.splitlines()[0][:60]}"
            fails[key] = fails.get(key, 0) + 1

        contexts.append(ctx)
        pages.append(pg)

    time.sleep(DWELL)
    if CLICK:
        for pg in pages:
            click_ad(pg)
    for ctx in contexts:
        try:
            ctx.close()
        except Exception:
            pass

    avg = total_load_time / BATCH_SIZE if BATCH_SIZE else 0
    return loaded, avg, fails, samples


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main() -> None:
    raw_urls = load_lines(URL_FILE)
    if not raw_urls:
        print("No URLs in urls.txt")
        return

    # Sanitize + validate every URL before it ever reaches goto().
    cleaned = [clean_url(u) for u in raw_urls]
    urls = [u for u in cleaned if u and _URL_RE.match(u)]

    for original, final in zip(raw_urls, cleaned):
        flag = "" if final and _URL_RE.match(final) else "  <-- DROPPED"
        print(f"URL: {repr(final)}{flag}")

    if not urls:
        print("No valid URLs after sanitizing - check urls.txt for hidden characters")
        return
    print(f"Loaded {len(urls)} valid url(s)")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=HEADLESS,
            channel="chromium",              # full Chromium + new headless
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-features=IsolateOrigins,site-per-process",
            ],
        )

        cycle = 0
        while True:
            cycle += 1

            if RECHECK_EVERY and cycle % RECHECK_EVERY == 0:
                print(f"[cycle {cycle}] re-validating proxies...")
                refresh_proxies()

            proxies = load_proxies()
            if not proxies:
                print("No working proxies available - running direct")
            else:
                print(f"[cycle {cycle}] using {len(proxies)} proxies")

            t0 = time.time()
            loaded, avg, fails, samples = run_cycle(browser, urls, proxies)
            elapsed = time.time() - t0

            print(f"cycle {cycle} done in {elapsed:.0f}s - {loaded}/{BATCH_SIZE} loaded, avg load {avg:.2f}s")
            if fails:
                top = sorted(fails.items(), key=lambda x: -x[1])[:5]
                print("   fails:", ", ".join(f"{k}={v}" for k, v in top))
            for s in samples:
                print("   sample:", s)

            if CYCLES and cycle >= CYCLES:
                break
            time.sleep(PAUSE)

        browser.close()


if __name__ == "__main__":
    main()