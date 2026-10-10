#!/usr/bin/env bash
#
# run_all.sh
# ----------
# One-command pipeline:
#   1. verify / install dependencies
#   2. validate input files
#   3. build working-proxies.txt via the checker
#   4. launch the traffic loop
#
# Usage:
#   chmod +x run_all.sh
#   ./run_all.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
RAW_PROXY_FILE="free-proxy-list.txt"    # your big raw dump
WORKING_FILE="working-proxies.txt"      # checker output -> loop input
URL_FILE="urls.txt"
CHECK_WORKERS=64
CHECK_TIMEOUT=8

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
info()  { printf '\033[1;34m[run_all]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[run_all]\033[0m %s\n' "$*"; }
fail()  { printf '\033[1;31m[run_all]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. DEPENDENCIES
# ---------------------------------------------------------------------------
info "Checking dependencies..."

command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH"
PY=python3

if ! "$PY" -c "import playwright" >/dev/null 2>&1; then
    info "Installing playwright..."
    pip install playwright
fi

if ! "$PY" -c "from playwright.sync_api import sync_playwright; sync_playwright" >/dev/null 2>&1; then
    fail "playwright import failed"
fi

# Install the chromium browser binary only if it's missing.
if ! ls ~/.cache/ms-playwright/chromium* >/dev/null 2>&1; then
    info "Installing chromium browser + system deps..."
    playwright install --with-deps chromium
else
    info "Chromium already installed."
fi

# ---------------------------------------------------------------------------
# 2. INPUT VALIDATION
# ---------------------------------------------------------------------------
info "Validating input files..."

[[ -f "$URL_FILE" ]]      || fail "Missing $URL_FILE (put your smartlink(s) in it)"
[[ -s "$URL_FILE" ]]      || fail "$URL_FILE is empty"

[[ -f "$RAW_PROXY_FILE" ]] || fail "Missing $RAW_PROXY_FILE (paste your raw proxy list in it)"
[[ -s "$RAW_PROXY_FILE" ]] || fail "$RAW_PROXY_FILE is empty"

[[ -f "check_proxies.py" ]] || fail "Missing check_proxies.py"
[[ -f "loop.py" ]]          || fail "Missing loop.py"

info "Inputs OK: $(wc -l < "$URL_FILE") url(s), $(wc -l < "$RAW_PROXY_FILE") raw proxy line(s)."

# ---------------------------------------------------------------------------
# 3. BUILD WORKING LIST
# ---------------------------------------------------------------------------
info "Testing proxies (this can take a while)..."
"$PY" check_proxies.py \
    -i "$RAW_PROXY_FILE" \
    -o "$WORKING_FILE" \
    -t "$CHECK_TIMEOUT" \
    -w "$CHECK_WORKERS"

WORKING_COUNT=$(grep -cve '^\s*$' "$WORKING_FILE" || true)
if [[ "$WORKING_COUNT" -eq 0 ]]; then
    fail "No working proxies found. Prune/refresh $RAW_PROXY_FILE and retry."
fi
info "Built $WORKING_FILE with $WORKING_COUNT working proxy line(s)."

# ---------------------------------------------------------------------------
# 4. LAUNCH LOOP
# ---------------------------------------------------------------------------
info "Starting loop.py (Ctrl-C to stop)..."
exec "$PY" loop.py