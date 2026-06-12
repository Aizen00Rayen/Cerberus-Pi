# Cerberus Pi — Deployment Runbook

Step-by-step deployment on a **Raspberry Pi 5 / Raspberry Pi OS Lite 64-bit
(Bookworm)**. Run everything from a console on the **management interface
(wlan0)** — never over `eth0`, which becomes passive and unaddressable.

---

## 0. Prerequisites

- Fresh Raspberry Pi OS Lite 64-bit, updated: `sudo apt update && sudo apt full-upgrade -y`
- A second NIC for management: built-in `wlan0`, or a USB-Ethernet adapter.
- `eth0` cabled to the SPAN/mirror port of the switch you want to monitor.
- Your SSH public key already on the device (hardening disables password login).

Copy this repository to the Pi, e.g.:

```bash
scp -r Cerberus-Pi pi@<pi-mgmt-ip>:~/
ssh pi@<pi-mgmt-ip>
cd ~/Cerberus-Pi
```

---

## 1. Install dependencies (Phase 1)

```bash
sudo ./scripts/cerberus_install.sh
```

This verifies hardware, installs all apt/pip/npm dependencies and kubo (IPFS),
creates the venv at `/opt/cerberus/venv`, and **auto-generates all secrets** into
`/opt/cerberus/secrets/.env`. Failures are logged to
`/opt/cerberus/logs/install_errors.log`.

> Review `/opt/cerberus/secrets/.env` and set optional keys (`NVD_API_KEY`,
> `LLM_PROVIDER`) if you want CVE enrichment / LLM-enhanced advice.

---

## 2. Harden & stealth (Phase 2)

```bash
sudo ./scripts/cerberus_harden.sh
```

⚠️ This locks SSH to key-only on port **2242**, enables UFW (default-deny), turns
**off ICMP echo** (no ping), and configures `eth0` for passive promiscuous
capture with a randomised MAC and **no IP**. After this, reconnect on
`wlan0:2242` if your session drops.

It also creates the LUKS-encrypted log volume and the `cerberus` service user.

---

## 3. Bring the platform up (Phases 3 + 9)

```bash
sudo ./scripts/cerberus_start.sh start
```

This performs one-time setup (installs systemd units + sudoers, substitutes
`HOME_NET`, initialises the private IPFS node, creates the PostgreSQL
role/database, generates a self-signed TLS cert, pulls Suricata rules) and then
starts every service in dependency order, finishing with a colour status board.

Create the single admin account:

```bash
sudo -u cerberus /opt/cerberus/venv/bin/python /opt/cerberus/backend/manage.py createsuperuser
```

Enable the real-time parsers (one per engine):

```bash
sudo systemctl enable --now cerberus-parser@suricata.service cerberus-parser@snort.service
```

---

## 4. Access the dashboard

Browse to **https://<pi-wlan0-ip>/** from a machine on the management network.
Accept the self-signed certificate (or install your own at
`/opt/cerberus/secrets/cerberus.{crt,key}`). Log in with the admin account.

---

## 5. Verify the Definition of Done

| Check | Command / action |
|-------|------------------|
| Engines running | `sudo ./scripts/cerberus_start.sh status` |
| No ping on eth0 | from another host: `ping <eth0-mac-target>` → no reply |
| Live threats | trigger a test (e.g. `nmap` the monitored segment), watch the dashboard feed |
| Scanner | Scanner page → Launch "Host Discovery" on `localnet` |
| IPFS archival | `POST /api/logs/daily/archive_now/` then press **Verify** |
| PDF report | Reports page → Generate → Download |
| Survives reboot | `sudo reboot`, then re-check status |

---

## Service management

```bash
sudo ./scripts/cerberus_start.sh status     # health dashboard
sudo ./scripts/cerberus_start.sh restart    # restart everything
sudo ./scripts/cerberus_start.sh stop       # stop all cerberus services
sudo systemctl status cerberus-suricata     # individual unit
journalctl -u cerberus-backend -f           # tail backend logs
```

## Troubleshooting

- **Backend won't start**: check `journalctl -u cerberus-backend`. Most often a
  DB connection issue — confirm `/opt/cerberus/secrets/.env` `POSTGRES_PASSWORD`
  matches the role created in step 3.
- **No alerts**: confirm `eth0` sees mirrored traffic (`sudo tcpdump -i eth0 -c 5`)
  and that `suricata-update` populated `/var/lib/suricata/rules`.
- **WS feed silent**: ensure `cerberus-parser@*` services are active and Redis is up.
