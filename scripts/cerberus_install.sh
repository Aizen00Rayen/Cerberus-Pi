#!/usr/bin/env bash
# =============================================================================
# Cerberus Pi — PHASE 1: Dependency Verification & Installation
# Yanova Solutions · INAPI Patent No. 240625
#
# Run on the Raspberry Pi 5 (Raspberry Pi OS Lite 64-bit, Bookworm) as root:
#     sudo ./scripts/cerberus_install.sh
#
# Idempotent: safe to re-run. Verifies first, installs only what is missing,
# logs every failure to /opt/cerberus/logs/install_errors.log, and exits with a
# clear message on the first fatal error.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_root
log "Cerberus Pi installer starting at $(date -Is)"
mkdir -p "$CERBERUS_LOGDIR" "$CERBERUS_SECRETS"
chmod 700 "$CERBERUS_SECRETS"

# -----------------------------------------------------------------------------
# 1.1 System checks
# -----------------------------------------------------------------------------
hdr "1.1  System checks"

# OS / architecture
ARCH="$(uname -m)"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  ok "OS: ${PRETTY_NAME:-unknown}"
else
  warn "Cannot read /etc/os-release"
fi
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
  ok "Architecture: $ARCH (ARM64)"
else
  warn "Architecture is $ARCH — expected aarch64. Continuing, but engine builds may differ."
fi

# Raspberry Pi 5 detection
if grep -qi "Raspberry Pi 5" /proc/cpuinfo /proc/device-tree/model 2>/dev/null; then
  ok "Hardware: Raspberry Pi 5 detected"
else
  warn "Could not confirm Raspberry Pi 5 from /proc/cpuinfo. Continuing anyway."
fi

# RAM (min 4 GB)
mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
mem_gb=$(( mem_kb / 1024 / 1024 ))
if (( mem_gb >= 4 )); then
  ok "RAM: ${mem_gb} GB (>= 4 GB required)"
else
  err "RAM: ${mem_gb} GB — minimum 4 GB required"
  log_error "Insufficient RAM: ${mem_gb}GB"
fi

# Free storage (min 16 GB on /)
free_gb="$(df -BG --output=avail / | tail -1 | tr -dc '0-9')"
if (( free_gb >= 16 )); then
  ok "Free storage on /: ${free_gb} GB (>= 16 GB required)"
else
  err "Free storage on /: ${free_gb} GB — minimum 16 GB required"
  log_error "Insufficient storage: ${free_gb}GB"
fi

# Network interfaces
for iface in eth0 wlan0; do
  if [[ -d "/sys/class/net/${iface}" ]]; then
    ok "Interface present: ${iface}"
  else
    warn "Interface missing: ${iface} (some features require it)"
  fi
done

# -----------------------------------------------------------------------------
# 1.2 System dependencies
# -----------------------------------------------------------------------------
hdr "1.2  System packages"

# REQUIRED packages — the install aborts if any of these cannot be installed.
APT_REQUIRED=(
  build-essential git curl wget unzip ca-certificates gnupg lsb-release
  python3 python3-pip python3-venv
  nodejs npm
  postgresql postgresql-contrib redis-server
  libpcap-dev libnet1-dev libpcre2-dev
  libyaml-dev libjansson-dev zlib1g-dev
  pkg-config autoconf automake libtool
  nmap arp-scan
  ufw fail2ban
  cryptsetup           # LUKS for log encryption (Phase 2.3)
)

# OPTIONAL packages — nice to have, but the install continues if they are not
# available on this Debian release. Notably:
#   wkhtmltopdf   — removed from Debian 13 (trixie); WeasyPrint (pip) makes the PDFs.
#   libpcre3-dev  — old PCRE1, dropped from trixie; libpcre2-dev (above) replaces it.
#   libdnet-dev   — package name varies by release (also libdumbnet-dev).
#   masscan/netdiscover — extra scanners; nmap + arp-scan cover the core needs.
APT_OPTIONAL=(
  wkhtmltopdf
  libpcre3-dev libdnet-dev libdumbnet-dev
  masscan netdiscover
)

export DEBIAN_FRONTEND=noninteractive
log "Refreshing apt index..."
if ! apt-get update -y >>"$INSTALL_LOG" 2>&1; then
  die "apt-get update failed — see $INSTALL_LOG"
fi

# apt_install_one <pkg> : install a single package; returns non-zero on failure
# (installing one at a time means a missing package never aborts the whole batch).
apt_install_one() {
  local p="$1"
  pkg_installed "$p" && { ok "$p"; return 0; }
  if apt-get install -y "$p" >>"$INSTALL_LOG" 2>&1 && pkg_installed "$p"; then
    ok "installed $p"; return 0
  fi
  return 1
}

failed_required=()
for p in "${APT_REQUIRED[@]}"; do
  apt_install_one "$p" || { err "failed $p"; log_error "apt required failed: $p"; failed_required+=("$p"); }
done

log "Optional packages (failures are non-fatal):"
for p in "${APT_OPTIONAL[@]}"; do
  apt_install_one "$p" || warn "optional package unavailable on this release: $p"
done

if (( ${#failed_required[@]} > 0 )); then
  die "Required packages failed to install: ${failed_required[*]} — see $INSTALL_LOG"
fi

# IPFS (kubo) — not in apt; fetch the ARM64 static binary.
hdr "1.2b  IPFS (kubo)"
if have ipfs; then
  ok "ipfs already installed: $(ipfs --version)"
else
  KUBO_VER="v0.29.0"
  KUBO_TARBALL="kubo_${KUBO_VER}_linux-arm64.tar.gz"
  KUBO_URL="https://dist.ipfs.tech/kubo/${KUBO_VER}/${KUBO_TARBALL}"
  log "Downloading kubo ${KUBO_VER}..."
  tmpd="$(mktemp -d)"
  if curl -fsSL "$KUBO_URL" -o "${tmpd}/${KUBO_TARBALL}" >>"$INSTALL_LOG" 2>&1; then
    # Supply-chain check: verify against the publisher's SHA-512 before extracting.
    if curl -fsSL "${KUBO_URL}.sha512" -o "${tmpd}/${KUBO_TARBALL}.sha512" >>"$INSTALL_LOG" 2>&1; then
      ( cd "$tmpd" && sha512sum -c "${KUBO_TARBALL}.sha512" ) >>"$INSTALL_LOG" 2>&1 \
        && ok "kubo checksum verified" \
        || die "kubo SHA-512 mismatch — aborting (possible tampered download)"
    else
      warn "Could not fetch kubo checksum; proceeding without verification"
    fi
    tar -xzf "${tmpd}/${KUBO_TARBALL}" -C "$tmpd" >>"$INSTALL_LOG" 2>&1
    ( cd "${tmpd}/kubo" && bash install.sh ) >>"$INSTALL_LOG" 2>&1 \
      && ok "ipfs installed: $(ipfs --version)" \
      || { err "kubo install.sh failed"; log_error "kubo install failed"; }
  else
    err "Could not download kubo from $KUBO_URL"
    log_error "kubo download failed"
  fi
  rm -rf "$tmpd"
fi

# -----------------------------------------------------------------------------
# 1.3 Python venv + packages
# -----------------------------------------------------------------------------
hdr "1.3  Python virtual environment"
VENV="${CERBERUS_ROOT}/venv"
if [[ ! -x "${VENV}/bin/python" ]]; then
  python3 -m venv "$VENV" || die "Failed to create venv at $VENV"
  ok "Created venv at $VENV"
else
  ok "venv exists at $VENV"
fi

"${VENV}/bin/pip" install --upgrade pip wheel setuptools >>"$INSTALL_LOG" 2>&1 \
  || die "pip self-upgrade failed"

# Prefer the pinned requirements file shipped with the repo; fall back to inline.
REQ="${SCRIPT_DIR}/../backend/requirements.txt"
if [[ -f "$REQ" ]]; then
  log "Installing Python deps from backend/requirements.txt"
  "${VENV}/bin/pip" install -r "$REQ" >>"$INSTALL_LOG" 2>&1 \
    || die "pip install -r requirements.txt failed — see $INSTALL_LOG"
else
  warn "requirements.txt not found; installing inline package set"
  "${VENV}/bin/pip" install \
    django djangorestframework django-cors-headers \
    channels channels-redis daphne \
    psycopg2-binary redis celery \
    python-nmap scapy \
    reportlab weasyprint \
    cryptography pycryptodome \
    python-dotenv gunicorn requests >>"$INSTALL_LOG" 2>&1 \
    || die "inline pip install failed — see $INSTALL_LOG"
fi
ok "Python packages installed"

# -----------------------------------------------------------------------------
# 1.4 Node.js frontend packages
# -----------------------------------------------------------------------------
hdr "1.4  Frontend (npm) packages"
FRONTEND="${SCRIPT_DIR}/../frontend"
if [[ -f "${FRONTEND}/package.json" ]]; then
  ( cd "$FRONTEND" && npm install >>"$INSTALL_LOG" 2>&1 ) \
    && ok "npm install complete" \
    || { err "npm install failed"; log_error "npm install failed"; }
  # Build the production SPA so Nginx has a dist/ to serve (Phase 6/9).
  ( cd "$FRONTEND" && npm run build >>"$INSTALL_LOG" 2>&1 ) \
    && ok "frontend build complete (dist/)" \
    || { err "npm run build failed"; log_error "npm run build failed"; }
else
  warn "frontend/package.json not found — skipping npm install/build"
fi

# -----------------------------------------------------------------------------
# 1.5 Secret generation (no hardcoded defaults — Constraint #3)
# -----------------------------------------------------------------------------
hdr "1.5  Generating secrets"
ENVF="${CERBERUS_SECRETS}/.env"
if [[ ! -f "$ENVF" ]] && [[ -f "${SCRIPT_DIR}/../.env.example" ]]; then
  cp "${SCRIPT_DIR}/../.env.example" "$ENVF"
fi
# Only generate if still the AUTO placeholder (idempotent).
grep -q '^DJANGO_SECRET_KEY=AUTO' "$ENVF" 2>/dev/null && \
  write_env_var DJANGO_SECRET_KEY "$(gen_hex)" && ok "Django secret key generated"
grep -q '^POSTGRES_PASSWORD=AUTO' "$ENVF" 2>/dev/null && \
  write_env_var POSTGRES_PASSWORD "$(gen_secret)" && ok "PostgreSQL password generated"
chmod 600 "$ENVF"
ok "Secrets stored in $ENVF (chmod 600)"

# -----------------------------------------------------------------------------
# 1.6 Post-install validation
# -----------------------------------------------------------------------------
hdr "1.6  Post-install validation"
validate() { # name  cmd...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$name OK"; else err "$name FAILED"; log_error "validate failed: $name"; return 1; fi
}
rc=0
validate "python3"     python3 --version            || rc=1
validate "venv python" "${VENV}/bin/python" --version|| rc=1
validate "node"        node --version               || rc=1
validate "npm"         npm --version                || rc=1
validate "postgres"    psql --version               || rc=1
validate "redis"       redis-server --version       || rc=1
validate "nmap"        nmap --version               || rc=1
validate "arp-scan"    arp-scan --version           || rc=1
validate "ufw"         ufw --version                || rc=1
# wkhtmltopdf is optional (absent on Debian 13); WeasyPrint handles PDF reports.
have wkhtmltopdf && validate "wkhtmltopdf" wkhtmltopdf --version || warn "wkhtmltopdf not present — PDFs use WeasyPrint"
have ipfs && validate "ipfs" ipfs --version || warn "ipfs not validated"

if (( rc != 0 )); then
  die "One or more critical components failed validation — see $INSTALL_LOG"
fi

hdr "Phase 1 complete"
log "All dependencies verified. Next: sudo ./scripts/cerberus_harden.sh"
