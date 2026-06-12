#!/usr/bin/env bash
# =============================================================================
# Cerberus Pi — PHASE 2: Hardening & Stealth Mode
# Makes the device secure and invisible on the monitored network.
#
#   sudo ./scripts/cerberus_harden.sh
#
# IMPORTANT ARCHITECTURE NOTE (read before running):
#   * eth0  = MONITORED interface. Passive only: promiscuous mode, no IP, no TX,
#             no ARP announcements. The device is invisible here. (Constraints #1,#2)
#   * wlan0 = MANAGEMENT interface. SSH + dashboard live here only.
#   Running this over an SSH session on eth0 will cut you off. Connect via wlan0.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
require_root

ENVF="${CERBERUS_SECRETS}/.env"
MONITOR_IFACE="$(grep -E '^MONITOR_IFACE=' "$ENVF" 2>/dev/null | cut -d= -f2)"; MONITOR_IFACE="${MONITOR_IFACE:-eth0}"
MGMT_IFACE="$(grep -E '^MGMT_IFACE=' "$ENVF" 2>/dev/null | cut -d= -f2)"; MGMT_IFACE="${MGMT_IFACE:-wlan0}"
SSH_PORT="$(grep -E '^SSH_PORT=' "$ENVF" 2>/dev/null | cut -d= -f2)"; SSH_PORT="${SSH_PORT:-2242}"

# -----------------------------------------------------------------------------
# 2.1 OS hardening
# -----------------------------------------------------------------------------
hdr "2.1  OS hardening"

log "Disabling unnecessary services"
for svc in bluetooth avahi-daemon triggerhappy cups cups-browsed; do
  if systemctl list-unit-files | grep -q "^${svc}"; then
    systemctl disable --now "$svc" >/dev/null 2>&1 && ok "disabled $svc" || warn "could not disable $svc"
  fi
done

# Create the unprivileged service account (Constraint #4): no sudo, no shell.
if ! id cerberus >/dev/null 2>&1; then
  useradd --system --home "$CERBERUS_ROOT" --shell /usr/sbin/nologin cerberus
  ok "created system user 'cerberus' (nologin)"
else
  ok "system user 'cerberus' exists"
fi
chown -R cerberus:cerberus "$CERBERUS_ROOT" 2>/dev/null || true

# SSH hardening: key-only, non-standard port, no root login.
log "Hardening SSH (key-only, port ${SSH_PORT})"
SSHD=/etc/ssh/sshd_config.d/99-cerberus.conf
cat > "$SSHD" <<EOF
# Cerberus Pi SSH hardening
Port ${SSH_PORT}
PasswordAuthentication no
PermitRootLogin no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
# Reachability is restricted to the management interface by UFW (allow on
# ${MGMT_IFACE}, deny on ${MONITOR_IFACE}); eth0 also carries no IP. We listen on
# all addresses because wlan0's address is DHCP-assigned and not known here.
ListenAddress 0.0.0.0
AllowUsers cerberus pi
EOF
chmod 644 "$SSHD"
if sshd -t 2>>"$INSTALL_LOG"; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "ssh restart skipped"
  ok "sshd configured & restarted"
else
  err "sshd config test failed — left unchanged. See $INSTALL_LOG"
  log_error "sshd -t failed"
fi

# Remove default 'pi' password → force key auth (account stays, password locked).
if id pi >/dev/null 2>&1; then
  passwd -l pi >/dev/null 2>&1 && ok "locked password for 'pi' user" || warn "could not lock 'pi'"
fi

# Kernel hardening.
log "Applying kernel hardening (sysctl)"
install -m 0644 "${SCRIPT_DIR}/../config/sysctl/99-cerberus.conf" /etc/sysctl.d/99-cerberus.conf
sysctl --system >>"$INSTALL_LOG" 2>&1 && ok "sysctl applied (ICMP echo ignored — ping disabled)" \
  || { err "sysctl --system failed"; log_error "sysctl failed"; }

# fail2ban: aggressive SSH jail (3 attempts → 1h ban).
log "Configuring fail2ban"
cat > /etc/fail2ban/jail.d/cerberus.conf <<EOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
maxretry = 3
findtime = 600
bantime  = 3600
backend  = systemd
EOF
systemctl enable --now fail2ban >/dev/null 2>&1 && ok "fail2ban active (3 tries → 1h ban)" || warn "fail2ban not started"

# UFW: default deny inbound; SSH + dashboard only on mgmt interface / localhost.
log "Configuring UFW firewall"
ufw --force reset >>"$INSTALL_LOG" 2>&1 || true
ufw default deny incoming  >>"$INSTALL_LOG" 2>&1
ufw default allow outgoing >>"$INSTALL_LOG" 2>&1
# SSH only on the management interface.
ufw allow in on "$MGMT_IFACE" to any port "$SSH_PORT" proto tcp >>"$INSTALL_LOG" 2>&1
# Dashboard HTTPS only on localhost (Nginx reverse proxy) + mgmt interface.
ufw allow in on lo to any port 443 proto tcp >>"$INSTALL_LOG" 2>&1
ufw allow in on "$MGMT_IFACE" to any port 443 proto tcp >>"$INSTALL_LOG" 2>&1
# Explicitly deny everything inbound on the monitored interface.
ufw deny in on "$MONITOR_IFACE" >>"$INSTALL_LOG" 2>&1
ufw --force enable >>"$INSTALL_LOG" 2>&1 && ok "UFW enabled (deny inbound; mgmt-only access)" || warn "UFW enable failed"

# -----------------------------------------------------------------------------
# 2.2 Network stealth on the monitored interface
# -----------------------------------------------------------------------------
hdr "2.2  Network stealth (${MONITOR_IFACE})"
# Install a systemd unit that, at boot:
#   - randomises MAC, brings the link up with NO IP (cannot be addressed),
#   - enables promiscuous mode (passive capture),
#   - disables ARP (device never announces itself). Constraints #1, #2.
STEALTH_UNIT=/etc/systemd/system/cerberus-stealth.service
cat > "$STEALTH_UNIT" <<EOF
[Unit]
Description=Cerberus Pi — stealth config for monitored interface ${MONITOR_IFACE}
Wants=network-pre.target
Before=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
# Randomise MAC, no IP, promiscuous on, ARP off. Passive monitoring only.
ExecStart=/sbin/ip link set ${MONITOR_IFACE} down
ExecStart=/usr/bin/env bash -c 'ip link set ${MONITOR_IFACE} address \$(printf "02:%02x:%02x:%02x:%02x:%02x" \$((RANDOM%256)) \$((RANDOM%256)) \$((RANDOM%256)) \$((RANDOM%256)) \$((RANDOM%256)))'
ExecStart=/sbin/ip link set ${MONITOR_IFACE} promisc on arp off
ExecStart=/sbin/ip link set ${MONITOR_IFACE} up
# Ensure no DHCP/addr ever assigned here.
ExecStart=/sbin/ip addr flush dev ${MONITOR_IFACE}

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$STEALTH_UNIT"
systemctl daemon-reload
systemctl enable cerberus-stealth.service >/dev/null 2>&1 && ok "stealth unit enabled (MAC random, promisc, ARP off, no IP)" \
  || warn "could not enable stealth unit"
# Apply now too (best-effort; will not run if you're on eth0).
systemctl start cerberus-stealth.service >/dev/null 2>&1 || warn "stealth start deferred to next boot"

# -----------------------------------------------------------------------------
# 2.3 Encrypted log storage (LUKS-backed loopback container)
# -----------------------------------------------------------------------------
hdr "2.3  Encrypted log storage"
# Uses a LUKS container file mounted at the logs dir. Key lives in secrets/ (root,600).
LUKS_IMG="${CERBERUS_ROOT}/secrets/logs.luks"
LUKS_KEY="${CERBERUS_SECRETS}/logs.key"
LUKS_NAME="cerberus_logs"
LUKS_SIZE_MB=4096
if have cryptsetup; then
  if [[ ! -f "$LUKS_IMG" ]]; then
    log "Creating ${LUKS_SIZE_MB}MB LUKS log container (one-time)"
    head -c 64 /dev/urandom > "$LUKS_KEY"; chmod 600 "$LUKS_KEY"; chown root:root "$LUKS_KEY"
    fallocate -l "${LUKS_SIZE_MB}M" "$LUKS_IMG" || dd if=/dev/zero of="$LUKS_IMG" bs=1M count="$LUKS_SIZE_MB"
    cryptsetup luksFormat --batch-mode "$LUKS_IMG" "$LUKS_KEY" >>"$INSTALL_LOG" 2>&1
    cryptsetup open "$LUKS_IMG" "$LUKS_NAME" --key-file "$LUKS_KEY" >>"$INSTALL_LOG" 2>&1
    mkfs.ext4 -q "/dev/mapper/${LUKS_NAME}" >>"$INSTALL_LOG" 2>&1
    cryptsetup close "$LUKS_NAME" >>"$INSTALL_LOG" 2>&1
    ok "LUKS log container created (key at $LUKS_KEY, root:600)"
  else
    ok "LUKS log container already present"
  fi
  # Mount unit that opens + mounts at boot.
  cat > /etc/systemd/system/cerberus-logs.mount <<EOF
[Unit]
Description=Cerberus Pi — encrypted log volume
DefaultDependencies=no
Before=cerberus-ids.target

[Mount]
What=/dev/mapper/${LUKS_NAME}
Where=${CERBERUS_LOGDIR}
Type=ext4
Options=defaults,noatime

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/cerberus-logs-unlock.service <<EOF
[Unit]
Description=Cerberus Pi — unlock encrypted log volume
DefaultDependencies=no
Before=cerberus-logs.mount

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/cryptsetup open ${LUKS_IMG} ${LUKS_NAME} --key-file ${LUKS_KEY}
ExecStop=/sbin/cryptsetup close ${LUKS_NAME}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable cerberus-logs-unlock.service >/dev/null 2>&1 || true
  ok "boot-time unlock + mount units installed"
else
  warn "cryptsetup unavailable — log encryption skipped"
fi

# -----------------------------------------------------------------------------
# 2.4 Application security: permissions
# -----------------------------------------------------------------------------
hdr "2.4  Permissions"
chmod 600 "$ENVF" 2>/dev/null || true
chmod 700 "$CERBERUS_SECRETS"
chown -R cerberus:cerberus "$CERBERUS_LOGDIR" 2>/dev/null || true
chmod -R 750 "$CERBERUS_LOGDIR" 2>/dev/null || true
ok "secrets 600, logs 750 (cerberus/root only)"

hdr "Phase 2 complete"
log "Host hardened & stealthed. Ping disabled on ${MONITOR_IFACE}. Manage via ${MGMT_IFACE}:${SSH_PORT}."
log "Next: sudo ./scripts/cerberus_start.sh start"
