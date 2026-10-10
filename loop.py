"""
loop.py
-------
Opens N tabs per cycle through random working proxies, dwells, clicks, closes.

Anti-fingerprint measures included:
  - WebRTC leak patched (forces WebRTC through the proxy)
  - Canvas fingerprint noise (per-context unique)
  - Coherent locale + timezone identity per tab
  - Proxy de-duplication within a batch (no same-IP collisions)

Reads proxies from working-proxies.txt (the checker's output) and re-validates
it before each cycle so expired proxies drop out automatically.

Usage:
    python loop.py
"""

import random
import time

from playwright.sync_api import sync_playwright

# Reuse the exact same parser the checker uses (single source of truth).
from check_proxies import load_lines, parse_proxy, run as run_proxy_check

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
BATCH_SIZE   = 100     # tabs per cycle (each on its own proxy)
DWELL        = 20      # seconds each tab stays open
CLICK        = True    # click the ad after dwell
CYCLES       = 0       # 0 = run forever
PAUSE        = 10      # seconds between cycles
LOAD_TIMEOUT = 30000   # ms
HEADLESS     = True

URL_FILE       = "urls.txt"
PROXY_FILE     = "working-proxies.txt"   # <- checker output, loop input
RAW_PROXY_FILE = "free-proxy-list.txt"   # used only when REFRESH_MODE == "full"

# Proxy hygiene
RECHECK_EVERY = 1          # re-validate proxies every N cycles (0 = never)
REFRESH_MODE  = "recheck"  # "recheck" = re-test working list; "full" = re-scan raw list
CHECK_TIMEOUT = 8.0
CHECK_WORKERS = 64

# ---------------------------------------------------------------------------
# IDENTITIES — coherent locale + timezone pairs (so a tab looks like one user,
# not a random mix). Swap in proxy-country-matched values if you have geo data.
# ---------------------------------------------------------------------------
PROFILES = [
    ("en-US", "America/New_York"),
    ("en-US", "America/Chicago"),
    ("en-US", "America/Los_Angeles"),
    ("en-US", "America/Phoenix"),
    ("en-GB", "Europe/London"),
    ("en-US", "America/New_York"),
    ("en-US", "America/Los_Angeles"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

VIEWPORTS = [(1366, 768), (1440, 900), (1536, 864), (1920, 1080), (1280, 720), (1600, 900)]

STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = { runtime: {} };
Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
"""

# Canvas noise — each context gets its own seed so the fingerprint differs.
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
# PROXY HANDLING
# ---------------------------------------------------------------------------
def load_proxies() -> list[dict]:
    """Load working proxies and convert to Playwright proxy dicts."""
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
    """Re-validate the proxy list so expired ones drop out before the cycle."""
    if REFRESH_MODE == "full":
        run_proxy_check(RAW_PROXY_FILE, PROXY_FILE, CHECK_TIMEOUT, CHECK_WORKERS)
    else:  # recheck the current working list in place
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
            # Prefer anchors that open a new tab or point off-domain.
            for el in anchors:
                try:
                    target = el.get_attribute("target") or ""
                    href = el.get_attribute("href") or ""
                    if target == "_blank" or "adsterra" in href or "auctionr" in href:
                        el.click(timeout=2000)
                        return
                except Exception:
                    pass
            # Otherwise click the first one.
            if anchors:
                try:
                    anchors[0].click(timeout=2000)
                    return
                except Exception:
                    pass
    except Exception:
        pass
    # Last resort: click mid-page.
    try:
        page.mouse.click(400, 400)
    except Exception:
        pass


def build_context(browser, proxy: dict | None):
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
        device_scale_factor=random.choice([1, 1, 2]),
    )
    ctx.add_init_script(STEALTH_JS)
    ctx.add_init_script(CANVAS_JS % random.randint(0, 255))
    return ctx


def run_cycle(browser, urls: list[str], proxies: list[dict]) -> None:
    contexts, pages = [], []

    # De-dupe proxies within the batch so no IP is reused in one cycle.
    if proxies:
        pool = random.sample(proxies, min(BATCH_SIZE, len(proxies)))
        # If batch > pool size, top up with extra random picks.
        while len(pool) < BATCH_SIZE:
            pool.append(random.choice(proxies))
    else:
        pool = [None] * BATCH_SIZE

    for i in range(BATCH_SIZE):
        proxy = pool[i] if i < len(pool) else (random.choice(proxies) if proxies else None)
        ctx = build_context(browser, proxy)
        pg = ctx.new_page()
        try:
            pg.goto(random.choice(urls), wait_until="domcontentloaded", timeout=LOAD_TIMEOUT)
        except Exception:
            pass
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


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main() -> None:
    urls = load_lines(URL_FILE)
    if not urls:
        print("No URLs in urls.txt")
        return

    print(f"Loaded {len(urls)} url(s)")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=HEADLESS,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                # Force WebRTC through the proxy so the real host IP doesn't leak.
                "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-features=IsolateOrigins,site-per-process",
            ],
        )

        cycle = 0
        while True:
            cycle += 1
            t0 = time.time()

            if RECHECK_EVERY and cycle % RECHECK_EVERY == 0:
                print(f"[cycle {cycle}] re-validating proxies...")
                refresh_proxies()

            proxies = load_proxies()
            if not proxies:
                print("No working proxies available - running direct")
            else:
                print(f"[cycle {cycle}] using {len(proxies)} working proxies")

            run_cycle(browser, urls, proxies)
            print(f"cycle {cycle} done in {time.time() - t0:.0f}s")

            if CYCLES and cycle >= CYCLES:
                break
            time.sleep(PAUSE)

        browser.close()


if __name__ == "__main__":
    main()
