#!/usr/bin/env bash
# Cerberus Pi — shared shell helpers (logging, colour, checks).
# Source this from the other scripts:  source "$(dirname "$0")/lib/common.sh"
#
# Designed for Raspberry Pi OS Lite (Debian Bookworm). POSIX-bash, no extras.

set -o errexit
set -o nounset
set -o pipefail

# --- Paths ---------------------------------------------------------------
export CERBERUS_ROOT="${CERBERUS_ROOT:-/opt/cerberus}"
export CERBERUS_LOGDIR="${CERBERUS_ROOT}/logs"
export CERBERUS_SECRETS="${CERBERUS_ROOT}/secrets"
export INSTALL_LOG="${CERBERUS_LOGDIR}/install_errors.log"

# --- Colour --------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'; C_BOLD=$'\033[1m'
else
  C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_BOLD=''
fi

OK="${C_GREEN}✅${C_RESET}"
FAIL="${C_RED}❌${C_RESET}"
WARN="${C_YELLOW}⚠️${C_RESET}"

# --- Logging -------------------------------------------------------------
log()   { printf '%s[cerberus]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '  %s %s\n' "$OK" "$*"; }
warn()  { printf '  %s %s\n' "$WARN" "$*"; }
err()   { printf '  %s %s\n' "$FAIL" "$*" >&2; }
hdr()   { printf '\n%s%s== %s ==%s\n' "$C_BOLD" "$C_BLUE" "$*" "$C_RESET"; }

# Append an error to the persistent install log (best-effort; dir may not exist yet).
log_error() {
  mkdir -p "$CERBERUS_LOGDIR" 2>/dev/null || true
  printf '%s  %s\n' "$(date -Is)" "$*" >> "$INSTALL_LOG" 2>/dev/null || true
}

# die <msg> : log, record, and exit non-zero.
die() {
  err "$*"
  log_error "FATAL: $*"
  exit 1
}

# --- Guards --------------------------------------------------------------
require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "This script must be run as root (use sudo)."
}

# have <cmd> : true if command exists on PATH.
have() { command -v "$1" >/dev/null 2>&1; }

# pkg_installed <debpkg> : true if a dpkg package is installed.
pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

# --- Secret generation ---------------------------------------------------
gen_secret()    { head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 48; }
gen_hex()       { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# write_env_var <key> <value> : idempotently set KEY=VALUE in the .env file.
write_env_var() {
  local key="$1" val="$2" envf="${CERBERUS_SECRETS}/.env"
  mkdir -p "$CERBERUS_SECRETS"
  touch "$envf"
  if grep -qE "^${key}=" "$envf" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$envf"
  else
    printf '%s=%s\n' "$key" "$val" >> "$envf"
  fi
  chmod 600 "$envf"
}
