#!/usr/bin/env bash
# =============================================================================
# Cerberus Pi — PHASE 9: Service Orchestration
#   sudo ./scripts/cerberus_start.sh {start|stop|restart|status}
#
# Startup order (each verified healthy before the next):
#   postgres → redis → ipfs → suricata + snort → backend → celery → celerybeat → nginx
# Also runs one-time setup: install units, init private IPFS, substitute HOME_NET,
# generate a self-signed cert, and create the DB role/database.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
require_root

ENVF="${CERBERUS_SECRETS}/.env"
MONITOR_IFACE="$(grep -E '^MONITOR_IFACE=' "$ENVF" 2>/dev/null | cut -d= -f2)"; MONITOR_IFACE="${MONITOR_IFACE:-eth0}"

# System services we depend on (distro-provided). Cerberus units are our own.
SYS_SERVICES=(postgresql redis-server)
CERBERUS_SERVICES=(
  cerberus-ipfs
  cerberus-suricata cerberus-snort
  cerberus-backend cerberus-celery cerberus-celerybeat
  cerberus-intelligence                       # Phase 11: isolated ML worker
  cerberus-engine-monitor
  cerberus-parser@suricata cerberus-parser@snort
)

# --- helpers ----------------------------------------------------------------
svc_active() { systemctl is-active --quiet "$1"; }

wait_healthy() { # unit timeout
  local unit="$1" t="${2:-20}"
  for ((i=0; i<t; i++)); do
    svc_active "$unit" && return 0
    sleep 1
  done
  return 1
}

detect_home_net() {
  # Derive HOME_NET from the management interface's subnet (eth0 has no IP).
  local cidr
  cidr="$(ip -o -f inet addr show "$(grep -E '^MGMT_IFACE=' "$ENVF" | cut -d= -f2)" 2>/dev/null \
          | awk '{print $4}' | head -1)"
  [[ -z "$cidr" ]] && cidr="192.168.1.0/24"
  # Normalise host address to network address (cheap: keep /24 family).
  echo "[$(echo "$cidr" | sed -E 's#\.[0-9]+/#.0/#')]"
}

# =============================================================================
one_time_setup() {
  hdr "One-time setup"

  # Install systemd units + sudoers + configs if not already in place.
  install -d /run/cerberus
  for u in "${REPO_DIR}"/systemd/cerberus-*.service "${REPO_DIR}"/systemd/cerberus-*.target; do
    [[ -e "$u" ]] && install -m 644 "$u" "/etc/systemd/system/$(basename "$u")"
  done
  install -m 644 "${REPO_DIR}/systemd/cerberus-parser@.service" /etc/systemd/system/ 2>/dev/null || true
  install -m 440 "${REPO_DIR}/systemd/sudoers.d-cerberus" /etc/sudoers.d/cerberus
  visudo -cf /etc/sudoers.d/cerberus >/dev/null && ok "sudoers installed & valid" || die "sudoers invalid"

  # Sync app code into /opt/cerberus (idempotent).
  install -d "${CERBERUS_ROOT}/scripts" "${CERBERUS_ROOT}/snort/rules" "${CERBERUS_ROOT}/frontend"
  cp -r "${REPO_DIR}/backend" "${CERBERUS_ROOT}/" 2>/dev/null || true
  cp "${REPO_DIR}/scripts/"*.py "${REPO_DIR}/scripts/"*.sh "${CERBERUS_ROOT}/scripts/" 2>/dev/null || true
  chmod +x "${CERBERUS_ROOT}/scripts/"*.sh 2>/dev/null || true
  # Built SPA for Nginx to serve. Build it now if cerberus_install.sh didn't.
  if [[ ! -d "${REPO_DIR}/frontend/dist" ]] && [[ -f "${REPO_DIR}/frontend/package.json" ]]; then
    ( cd "${REPO_DIR}/frontend" && npm install >>"$INSTALL_LOG" 2>&1 && npm run build >>"$INSTALL_LOG" 2>&1 ) || warn "frontend build failed"
  fi
  cp -r "${REPO_DIR}/frontend/dist" "${CERBERUS_ROOT}/frontend/" 2>/dev/null || warn "no frontend/dist to deploy"
  # Snort community + local rules into place.
  cp "${REPO_DIR}/config/snort/rules/"*.rules "${CERBERUS_ROOT}/snort/rules/" 2>/dev/null || true

  # Engine configs with HOME_NET substituted.
  local HN; HN="$(detect_home_net)"
  ok "HOME_NET detected: ${HN}"
  install -d /etc/suricata
  sed "s#__HOME_NET__#${HN}#g" "${REPO_DIR}/config/suricata/suricata.yaml" > /etc/suricata/suricata.yaml
  sed "s#__HOME_NET__#${HN}#g" "${REPO_DIR}/config/snort/snort.lua" > "${CERBERUS_ROOT}/snort/snort.lua"
  ok "engine configs written"

  # Nginx site.
  install -m 644 "${REPO_DIR}/config/nginx/cerberus.conf" /etc/nginx/sites-available/cerberus.conf 2>/dev/null || true
  ln -sf /etc/nginx/sites-available/cerberus.conf /etc/nginx/sites-enabled/cerberus.conf 2>/dev/null || true
  rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

  # Self-signed cert if none provided.
  if [[ ! -f "${CERBERUS_SECRETS}/cerberus.crt" ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
      -keyout "${CERBERUS_SECRETS}/cerberus.key" \
      -out "${CERBERUS_SECRETS}/cerberus.crt" \
      -subj "/C=DZ/O=Yanova Solutions/CN=cerberus.local" >>"$INSTALL_LOG" 2>&1
    chmod 600 "${CERBERUS_SECRETS}/cerberus.key"
    ok "self-signed TLS cert generated"
  fi

  # PostgreSQL role + database (socket auth).
  systemctl enable --now postgresql >/dev/null 2>&1 || true
  local PGPW; PGPW="$(grep -E '^POSTGRES_PASSWORD=' "$ENVF" | cut -d= -f2)"
  sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='cerberus'" 2>/dev/null | grep -q 1 || \
    sudo -u postgres psql -c "CREATE ROLE cerberus LOGIN PASSWORD '${PGPW}';" >>"$INSTALL_LOG" 2>&1
  sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='cerberus'" 2>/dev/null | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE cerberus OWNER cerberus;" >>"$INSTALL_LOG" 2>&1
  ok "PostgreSQL role + database ready (socket only)"

  # Private IPFS init.
  local IPFS_PATH="${CERBERUS_ROOT}/.ipfs"
  if [[ ! -d "$IPFS_PATH" ]]; then
    sudo -u cerberus IPFS_PATH="$IPFS_PATH" ipfs init --profile server >>"$INSTALL_LOG" 2>&1 || true
    # Lock the node down: localhost API/gateway, no swarm announce (Constraint #5).
    sudo -u cerberus IPFS_PATH="$IPFS_PATH" ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001
    sudo -u cerberus IPFS_PATH="$IPFS_PATH" ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
    sudo -u cerberus IPFS_PATH="$IPFS_PATH" ipfs config --json Swarm.DisableNatPortMap true
    sudo -u cerberus IPFS_PATH="$IPFS_PATH" ipfs config --json Addresses.Announce '[]'
    sudo -u cerberus IPFS_PATH="$IPFS_PATH" ipfs bootstrap rm --all >>"$INSTALL_LOG" 2>&1 || true
    ok "private IPFS node initialised (localhost-only, no swarm)"
  fi

  # Suricata ruleset.
  have suricata-update && suricata-update >>"$INSTALL_LOG" 2>&1 && ok "Suricata rules updated" || warn "suricata-update skipped"

  systemctl daemon-reload
  chown -R cerberus:cerberus "$CERBERUS_ROOT"
}

# =============================================================================
do_start() {
  one_time_setup
  hdr "Starting services (ordered)"

  for s in "${SYS_SERVICES[@]}"; do
    systemctl enable --now "$s" >/dev/null 2>&1
    wait_healthy "$s" 20 && ok "$s" || { err "$s failed"; log_error "start failed: $s"; }
  done

  # Ordered cerberus units.
  local ordered=(cerberus-ipfs cerberus-suricata cerberus-snort cerberus-backend \
                 cerberus-celery cerberus-celerybeat cerberus-intelligence \
                 cerberus-engine-monitor \
                 "cerberus-parser@suricata" "cerberus-parser@snort")
  for s in "${ordered[@]}"; do
    systemctl enable --now "$s" >/dev/null 2>&1
    if wait_healthy "$s" 25; then ok "$s"; else err "$s failed to become active"; log_error "start failed: $s"; fi
  done

  # Phase 11: train v1 ML models from bundled datasets if none exist yet (idempotent).
  hdr "AI models (Phase 11)"
  sudo -u cerberus bash -c "cd ${CERBERUS_ROOT}/backend && \
    set -a; . ${ENVF}; set +a; \
    ${CERBERUS_ROOT}/venv/bin/python manage.py ml_bootstrap" >>"$INSTALL_LOG" 2>&1 \
    && ok "ML models bootstrapped" || warn "ml_bootstrap reported issues (see $INSTALL_LOG)"

  systemctl enable cerberus-ids.target >/dev/null 2>&1 || true
  nginx -t >>"$INSTALL_LOG" 2>&1 && systemctl restart nginx && ok "nginx" || { err "nginx config test failed"; log_error "nginx -t failed"; }

  do_status
}

do_stop() {
  hdr "Stopping Cerberus services"
  local all=("${CERBERUS_SERVICES[@]}")
  # Reverse order for a clean shutdown.
  for ((idx=${#all[@]}-1; idx>=0; idx--)); do
    systemctl stop "${all[idx]}" 2>/dev/null && ok "stopped ${all[idx]}" || true
  done
  systemctl stop nginx 2>/dev/null || true
}

do_status() {
  hdr "Cerberus Pi status dashboard"
  printf '  %-28s %s\n' "monitored iface" "${MONITOR_IFACE} (passive, ping disabled)"
  local all=("${SYS_SERVICES[@]}" "${CERBERUS_SERVICES[@]}" nginx)
  for s in "${all[@]}"; do
    if svc_active "$s"; then
      printf '  %s %-32s %s\n' "$OK" "$s" "${C_GREEN}active${C_RESET}"
    else
      printf '  %s %-32s %s\n' "$FAIL" "$s" "${C_RED}inactive${C_RESET}"
    fi
  done
}

case "${1:-status}" in
  start)   do_start ;;
  stop)    do_stop ;;
  restart) do_stop; sleep 2; do_start ;;
  status)  do_status ;;
  *) echo "usage: $0 {start|stop|restart|status}"; exit 2 ;;
esac
