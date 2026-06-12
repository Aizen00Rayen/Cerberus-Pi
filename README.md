<div align="center">

# 🛡️ Cerberus Pi

### Stealth Intrusion Detection & Prevention System for Raspberry Pi 5

**Yanova Solutions (Algeria) · INAPI Patent No. 240625**

*Built in Algeria. Protecting Algerian networks.*

</div>

---

## 📖 What is Cerberus Pi?

Cerberus Pi turns a Raspberry Pi 5 into a **production-grade, invisible network
sensor**. You plug `eth0` into the mirror/SPAN port of a switch; the Pi watches
all traffic passively (it has no IP on that interface and does not respond to
ping), runs **two IDS/IPS engines side by side** (Suricata + Snort 3), and
presents everything through a secure, real-time web dashboard reachable only on
a separate management interface.

It does seven things:

1. **Detects intrusions** with Suricata + Snort 3, normalising both engines into
   one unified threat stream.
2. **Hardens & hides the host** — randomised MAC, promiscuous-but-silent `eth0`,
   key-only SSH on a non-standard port, UFW default-deny, fail2ban, kernel
   hardening, and LUKS-encrypted logs.
3. **Prioritises threats with AI** — every alert gets rule-based remediation
   advice, optionally enhanced by an LLM (OpenAI or local Ollama).
4. **Scans the network from every angle** — host discovery, port/service/OS
   detection, vulnerability scans with CVE lookups, and per-host risk scoring.
5. **Archives logs immutably to IPFS** — daily, compressed, SHA-256-hashed, and
   independently verifiable.
6. **Generates professional PDF threat reports** on demand, each stamped with a
   SHA-256 integrity hash.
7. **Stays up** — every component is a `systemd` service that survives reboot,
   with a watchdog that restarts a crashed engine within 30 seconds.

---

## 🏗️ Architecture

```
                       ┌─────────────────────────────────────────────┐
   MONITORED LAN       │                RASPBERRY PI 5                │
   (switch SPAN) ──────┤ eth0  ── passive, promiscuous, NO IP, no TX │
                       │   │                                         │
                       │   ▼                                         │
                       │  Suricata ─┐        ┌─ Snort 3              │
                       │            ▼        ▼                       │
                       │        eve.json   alert_json                │
                       │            └───┬────┘                       │
                       │                ▼                            │
                       │        threat_parser  ──► PostgreSQL        │
                       │         (normalise,         (Unix socket)   │
                       │          dedup, advice)       │             │
                       │                │              ▼             │
                       │         Django + DRF + Channels (ASGI)      │
                       │           │        │         │              │
                       │       Celery    Redis    WebSockets         │
                       │         │                     │             │
                       │   IPFS (private)       Nginx (HTTPS) ◄───────── ADMIN
                       │   scans / reports           │             │   (wlan0 only)
                       │                         React SPA          │
   MGMT LAN ───────────┤ wlan0 ── SSH:2242 + dashboard HTTPS         │
                       └─────────────────────────────────────────────┘
```

**Two-interface stealth model (non-negotiable):**

| Interface | Role | Posture |
|-----------|------|---------|
| `eth0` | Monitored | Promiscuous capture, randomised MAC, **no IP, never transmits, no ARP, no ping** — invisible |
| `wlan0` | Management | The *only* way in: SSH (key-only, port 2242) and dashboard (HTTPS) |

### Technology stack

| Layer | Technology |
|-------|-----------|
| IDS/IPS engines | Suricata, Snort 3 |
| Backend | Python 3.11, Django 5, Django REST Framework, Channels (ASGI/WebSockets) |
| Async / scheduling | Celery + Celery Beat, Redis |
| Database | PostgreSQL (Unix-socket only) |
| Frontend | React 18, Vite, Tailwind CSS, Recharts, React Query |
| Reverse proxy | Nginx (HTTPS, HTTP→HTTPS redirect) |
| Immutable storage | IPFS (kubo), private node |
| Reports | WeasyPrint (HTML→PDF), SHA-256 integrity |
| Scanning | nmap, arp-scan, masscan, NVD CVE API |
| Host security | UFW, fail2ban, LUKS, sysctl hardening |
| Service management | systemd (auto-start, watchdog) |

---

## 🗄️ Data schemas

All models live in `backend/<app>/models.py`. Core entities:

### `Threat` — a normalised IDS/IPS alert
| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | datetime | When the alert fired |
| `engine` | enum | `suricata` \| `snort` |
| `severity` | enum | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` |
| `category` | string | e.g. "Port Scan", "Malware C2" |
| `src_ip` / `dst_ip` | IP | Source / destination |
| `src_port` / `dst_port` | int | |
| `protocol` | string | tcp/udp/icmp |
| `signature` | text | Rule message |
| `advice` | text | AI/rule-based remediation |
| `is_blocked` | bool | Set when the source IP is firewalled |
| `dedup_key` | hash | Suppresses repeats (same sig+src+dst within 60s) |
| `raw_alert` | json | Full original event |

### `NetworkHost` — a discovered device
`ip_address`, `mac_address`, `hostname`, `os_detected`, `open_ports` (json),
`vulnerabilities` (json, CVE list), `risk_score` (0–100), `first_seen`, `last_seen`.

### `ScanResult` — one scan run
`scan_type` (discovery/port/os/vuln/service/stealth/udp/arp), `target`,
`status` (queued/running/done/failed), `findings` (json), `host_count`,
`vulnerability_count`, timestamps.

### `LogEntry` & `DailyLogArchive` — the log vault
`LogEntry`: `date`, `source`, `level`, `message`, `raw`, `ipfs_cid`.
`DailyLogArchive`: `date`, `log_count`, `ipfs_cid`, `file_hash` (SHA-256),
`size_bytes`, `verified`.

### `Report` — a generated PDF
`title`, `report_type` (daily/weekly/monthly/custom), `status`, `period_start`,
`period_end`, `pdf_path`, `sha256` (cover-page hash), `ipfs_cid`.

### `EngineStatus` — live engine health
`engine_name`, `status` (running/stopped/crashed/restarting), `pid`, `uptime`,
`alerts_count`, `last_heartbeat`, `last_restart`, `restart_count`.

### `LoginAudit` — Phase 10 security log
`username`, `success`, `ip_address`, `user_agent`, `timestamp`.

---

## 🔌 API reference (all under `/api/`, all require authentication)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/api/threats/` | List threats (filter: severity, engine, category, IP; `?search=`) |
| `GET` | `/api/threats/{id}/` | Threat detail + raw alert |
| `GET` | `/api/threats/summary/` | Severity counts + top attackers (dashboard) |
| `POST` | `/api/threats/{id}/block/` | Block the source IP (iptables) |
| `GET` | `/api/scanner/hosts/` | Discovered hosts |
| `GET` | `/api/scanner/results/` | Scan history |
| `POST` | `/api/scanner/results/scan/` | Launch a scan (validated target) |
| `GET` | `/api/logs/daily/` | Daily IPFS archives |
| `POST` | `/api/logs/daily/{id}/verify/` | Re-fetch from IPFS, check hash |
| `POST` | `/api/logs/daily/archive_now/` | Trigger archival |
| `GET` | `/api/logs/entries/by-date/YYYY-MM-DD/` | Logs for a day (`?search=`) |
| `POST` | `/api/reports/generate/` | Queue a PDF report |
| `GET` | `/api/reports/{id}/download/` | Download the PDF |
| `GET` | `/api/engine/status/` | Engine health |
| `POST` | `/api/engine/status/restart/` | Start/stop/restart an engine |
| `GET` | `/api/engine/status/health/` | Pi CPU/RAM/disk/temperature |
| `POST` | `/api/auth/login/` | Login (rate-limited 5/10min) |
| `POST` | `/api/auth/logout/` · `GET /api/auth/me/` · `GET /api/auth/csrf/` | Session |
| `WS` | `/ws/threats/` | Real-time threat stream |
| `WS` | `/ws/engine/` | Real-time engine status |

---

## 🚀 Tutorial: running Cerberus Pi on a Raspberry Pi 5

> ⚠️ This repository is **developed on a Windows/x86 machine** but **runs on the
> Pi**. Off-Pi we verify syntax, the Django system check, migrations, and the
> frontend build; the OS-level steps (engines, hardening, systemd, stealth) only
> execute on the device. Run the scripts **on the Pi**, over the **management
> interface (`wlan0`)** — never over `eth0`.

### Step 0 — Hardware & OS

- Raspberry Pi 5 (8 GB recommended), 16 GB+ storage.
- **Raspberry Pi OS Lite 64-bit** (Bookworm), fully updated.
- A management network path: built-in `wlan0` **or** a USB-Ethernet adapter.
- `eth0` cabled to your switch's **mirror/SPAN port**.
- Your SSH **public key** already added (hardening disables password login).

```bash
sudo apt update && sudo apt full-upgrade -y
```

### Step 1 — Get the code onto the Pi

```bash
git clone https://github.com/Aizen00Rayen/Cerberus-Pi.git
cd Cerberus-Pi
```

### Step 2 — Install dependencies (Phase 1)

```bash
sudo ./scripts/cerberus_install.sh
```

Verifies hardware (Pi 5, ≥4 GB RAM, ≥16 GB free), installs all apt/pip/npm
packages and IPFS (**checksum-verified**), builds the React SPA, creates the
venv at `/opt/cerberus/venv`, and **auto-generates every secret** into
`/opt/cerberus/secrets/.env` (chmod 600). Errors are logged to
`/opt/cerberus/logs/install_errors.log`.

> Optional: edit `/opt/cerberus/secrets/.env` to add an `NVD_API_KEY` (richer
> CVE data) or set `LLM_PROVIDER=ollama|openai` for AI-enhanced advice.

### Step 3 — Harden & stealth the host (Phase 2)

```bash
sudo ./scripts/cerberus_harden.sh
```

⚠️ After this, the Pi **stops responding to ping**, SSH becomes **key-only on
port 2242**, UFW is **default-deny**, and `eth0` goes **silent** (random MAC, no
IP, promiscuous). If your session drops, reconnect on `wlan0`:

```bash
ssh -p 2242 pi@<pi-wlan0-ip>
```

### Step 4 — Launch the platform (Phases 3 + 9)

```bash
sudo ./scripts/cerberus_start.sh start
```

Performs one-time setup (systemd units, restricted sudoers, `HOME_NET`
substitution, private IPFS init, PostgreSQL role/DB, self-signed TLS cert,
Suricata ruleset) then starts every service in dependency order and prints a
colour status board.

Create the single admin account and enable the live parsers:

```bash
sudo -u cerberus /opt/cerberus/venv/bin/python /opt/cerberus/backend/manage.py createsuperuser
sudo systemctl enable --now cerberus-parser@suricata.service cerberus-parser@snort.service
```

### Step 5 — Open the dashboard

Browse to **`https://<pi-wlan0-ip>/`** from a machine on the management network,
accept the self-signed certificate, and log in.

### Step 6 — Verify it works

```bash
sudo ./scripts/cerberus_start.sh status        # health dashboard
```

| Check | How |
|-------|-----|
| No ping on eth0 | From another host, ping the monitored segment → no reply |
| Live threats | Generate test traffic, watch the dashboard feed update instantly |
| Scanner | Scanner page → Launch "Host Discovery" on `localnet` |
| IPFS vault | `POST /api/logs/daily/archive_now/` → press **Verify** |
| PDF report | Reports page → Generate → Download |
| Survives reboot | `sudo reboot`, re-check status |

### Day-to-day management

```bash
sudo ./scripts/cerberus_start.sh {start|stop|restart|status}
sudo systemctl status cerberus-suricata
journalctl -u cerberus-backend -f
```

Full runbook & troubleshooting: **[DEPLOYMENT.md](DEPLOYMENT.md)**.

---

## 🧠 AI Anomaly Detection (Phase 11)

Cerberus Pi ships a **self-learning anomaly-detection layer** that runs *entirely
on the Pi* — no GPU, no cloud, no data ever leaves the device. It complements the
signature engines (Suricata/Snort): the rule engines catch *known* patterns, the
AI layer catches *behaviour* and *obfuscated variants* that don't match a rule,
and it gets better over time as the admin confirms or rejects its findings.

It detects **four OWASP-aligned attack classes**, each with a model chosen to fit
both the problem and the Pi's CPU-only, ARM64, ~8 GB budget.

### The four models

| Attack | Algorithm | Input / features | Why this model | Output |
|--------|-----------|------------------|----------------|--------|
| **SQL Injection** | TF-IDF (char 2–5-grams) + **Logistic Regression** | HTTP payload text + 10 handcrafted features (keyword count, special-char ratio, comment/union/sleep flags, encoding…) | Linear model on character n-grams is fast (<3 ms), tiny, and robust to obfuscation/encoding | `confidence` 0–1 |
| **Cross-Site Scripting** | TF-IDF (char 3–6-grams) + **SVM (RBF, probabilistic)** | Parameter value + 10 features (tag count, event handlers, `javascript:`, entropy, data-URI…) | Char n-grams + SVM resist case-folding / split-tag obfuscation; calibrated for a real probability | `confidence` 0–1 |
| **Brute Force** | **Isolation Forest** (unsupervised) | Per-IP behavioural window: request count, fail ratio, unique users/endpoints, inter-request timing & regularity, deviation from baseline | *No attack labels needed* — it learns "normal" and flags outliers, so it catches novel automation patterns | `anomaly_score` → `confidence` |
| **DoS / DDoS** | **Statistical thresholds** + optional **quantised LSTM (TFLite)** | Traffic windows: pps, bps, SYN/ACK/RST rates, connection rate, deviation from per-interface baseline | Layer 1 is instant (<1 ms) and always on; Layer 2 (sequence model) catches slow-rate/low-and-slow floods | verdict + `confidence` |

Models are trained inside `/opt/cerberus/venv` (scikit-learn), saved to
`/opt/cerberus/intelligence/models/<attack>/` as versioned artifacts, and loaded
**once** into memory at startup — inference never reloads from disk.

### How a detection flows (inference path)

```
Suricata/Snort alert ──► threat_parser saves a Threat
                               │  (additive hook — never blocks the IDS)
                               ▼
              intelligence.integration.run_ml_analysis()
                               │  picks a detector by category/signature
                               ▼
        CerberusDetector (models cached in RAM, thresholds cached 30s)
          SQLi / XSS  → predict_proba                 confidence ≥ threshold?
          BruteForce  → IsolationForest.decision_fn   score < threshold?
          DoS         → threshold compare, then LSTM   over baseline?
                               │  if it fires:
                               ▼
        AnomalyDetection row (confidence, top-3 human reasons, payload≤500c,
                              raw feature vector, linked to the Threat)
                               │
                               ▼
        /ws/intelligence/  ──►  AI Intelligence page updates in real time
```

Every detection is **explainable**: the model returns the top 3 human-readable
reasons (e.g. *"UNION keyword detected"*, *"Inline event handler (onerror)"*,
*"4.2× normal request volume"*) so the admin can judge it at a glance.
Inference budget is **<15 ms/event** (measured: SQLi ~2.5 ms, XSS ~4 ms,
Brute Force ~14 ms, DoS statistical ~0.01 ms).

### How it teaches itself — the self-learning lifecycle

The system improves through a continuous loop. There are four stages:

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │                                                                        │
   ▼                                                                        │
① 72h BASELINE ──► ② INITIAL TRAINING ──► ③ LIVE DETECTION + ADMIN FEEDBACK │
   (learn normal)     (from baseline +        (confirm ✅ / reject ❌ each    │
                       bundled datasets)       detection)                    │
                                                       │                     │
                                                       ▼                     │
                                            ④ WEEKLY AUTO-RETRAIN ───────────┘
                                          (feedback ⇒ better models, versioned)
```

**① The 72-hour baseline phase (learning "normal").**
On first deployment the system spends 72 hours (configurable via
`ML_BASELINE_HOURS`) *passively observing* your network. Every 5 minutes a Celery
task updates a per-IP `BaselineProfile` (requests/min, failed-auth rate, payload
sizes, common ports/endpoints/user-agents, packets & bytes per second) using an
exponential moving average, plus per-interface traffic baselines for DoS.

During this phase the ML models aren't trained yet, so detection runs in
**fallback mode**: SQLi/XSS use the bundled signature datasets, brute force uses a
static rule (>10 failed logins/min), and DoS uses statistical thresholds only.
The dashboard shows a pill: **🟡 Learning (Xh remaining)**.

**② Initial training (waking up).**
When 72 h elapse, `BaselineProfile`s are marked complete and the system
automatically queues training for all four models. SQLi/XSS train on the
**bundled seed datasets** (`backend/intelligence/datasets/*.csv` — curated SQLi &
XSS payloads vs. realistic benign traffic). Brute Force fits an Isolation Forest
to the *normal* behavioural profiles it just learned. DoS derives thresholds
(`mean + 3σ`) from the observed traffic. The pill flips to **🟢 Active**.
*(For convenience, `cerberus_start.sh` also runs `manage.py ml_bootstrap` at
deploy so v1 models exist from the bundled data on day one.)*

**③ Live detection + the human feedback loop (getting smarter).**
Every detection lands on the **AI Intelligence** page with a confidence bar and
its reasons. The admin clicks one of two buttons:

- **✅ Confirm Threat** → the payload becomes a labelled *positive* example.
- **❌ False Positive** → it becomes a labelled *negative* and is excluded next time.

These verdicts are appended to per-attack training CSVs in
`/opt/cerberus/intelligence/training_data/` (chmod 600 — they contain raw
payloads). This is how the system adapts to *your* network's traffic and reduces
false positives over time.

**④ Weekly automatic retraining (improving — safely).**
Every **Sunday 02:00** (Celery Beat) the system retrains all four models on
*bundled data + everything the admin has confirmed/rejected since*. Retraining is
hardened against **model poisoning** and **regressions**:

- Only **admin-verdicted** samples ever enter training data (no auto-labelling).
- A **minimum number of confirmed samples** is required before a model changes.
- Each new model is evaluated on a 20% holdout; it is **promoted to "current"
  only if it does not lose more than 2% accuracy** vs. the live model.
- The previous model is **archived, never deleted** — every version is kept, so
  you can roll back. Each `MLModel` row records accuracy, F1, precision, recall,
  sample count and version.

You can also retrain on demand from the dashboard (**Retrain Now**) or via
`POST /api/intelligence/models/retrain/` — it runs on a **dedicated, isolated
Celery worker** (`cerberus-intelligence.service`, `--queues=intelligence`) so
training never starves the main IDS pipeline.

### Tuning sensitivity

Detection thresholds (e.g. SQLi ≥ 0.65, XSS ≥ 0.70, DoS = 3× baseline, SYN/ACK
ratio > 10) are adjustable live from the **Threshold Settings** panel or
`POST /api/intelligence/thresholds/`. They're cached in-process (30 s TTL) so
changes apply almost immediately without restarting and without slowing the
inference path. Lower thresholds = more sensitive (more alerts, more false
positives); the feedback loop then helps you pull the false-positive rate back down.

### New API & data (Phase 11)

```
GET  /api/intelligence/models/                  list models + accuracy/F1/version
POST /api/intelligence/models/retrain/          retrain all or one model
GET  /api/intelligence/detections/              ML detections (paginated)
POST /api/intelligence/detections/{id}/verdict/ admin feedback (confirm/reject)
GET  /api/intelligence/baseline/status/         72h phase + progress
GET  /api/intelligence/baseline/profiles/       per-IP behavioural profiles
GET  /api/intelligence/training/                training-job history
GET  /api/intelligence/stats/                   detection + verdict stats
GET/POST /api/intelligence/thresholds/          read / tune detection thresholds
WS   /ws/intelligence/                           real-time detection feed
```

New models: `MLModel`, `AnomalyDetection` (FK → existing `Threat`),
`BaselineProfile`, `TrainingJob`. The module is **fully additive** — it only
references existing models via a nullable foreign key and a single guarded hook
in the threat parser, so the core IDS works with or without it.

### Known limitations (honest)

- **DOM-based XSS** executes client-side and isn't visible to a network sensor.
- **Distributed brute force** (1 attempt per IP) is only partially detectable.
- **Slow-rate DoS** (Slowloris-style) relies on the LSTM layer; detection is
  lower than for volumetric floods.
- **TLS-encrypted payloads** hide SQLi/XSS content from inspection (mirror
  decrypted traffic or terminate TLS upstream if you need this).
- The **DoS LSTM** needs full TensorFlow on the Pi and ≥50 confirmed samples; the
  always-on statistical layer covers volumetric attacks in the meantime.

### Security of the ML module

Models are owned by the `cerberus` user (chmod 750); training-data CSVs are
chmod 600 (raw payloads are sensitive); stored `payload_sample`s are truncated to
500 characters; inference is 100% offline; and the TFLite interpreter is guarded
by a lock. Training runs on an isolated Celery queue with bounded concurrency.

---

## 🔒 Security model

Cerberus Pi is an appliance, and security *is* the product. Enforced in code:

- **Passive monitoring** — `eth0` never transmits; the device is invisible on
  the monitored LAN and does not answer ping.
- **Least privilege** — services run as the unprivileged `cerberus` user. The
  only two privileged actions (block an IP, restart an engine) go through a
  **narrow `sudoers` allow-list** ([systemd/sudoers.d-cerberus](systemd/sudoers.d-cerberus))
  that permits *exactly* those commands and nothing else.
- **No hardcoded secrets** — all keys/passwords are generated at install. The
  backend **refuses to boot in production** with a missing/placeholder secret key.
- **Injection-hardened** — scan targets are strictly validated (only `localnet`
  or private/loopback/link-local IPv4/CIDR), killing argument-injection and
  external-scan abuse. All subprocess calls use list form, never a shell.
- **Locked-down data plane** — PostgreSQL on a Unix socket only, Redis on
  localhost, IPFS private (no public gateway/swarm/API), logs LUKS-encrypted and
  readable only by `cerberus`/root.
- **Authenticated everywhere** — every API endpoint and WebSocket requires a
  session; login is rate-limited (5/10 min) and fully audited; sessions expire
  after 30 minutes; HTTPS-only cookies, HSTS, CSRF, and `X-Frame-Options: DENY`.
- **Integrity** — daily logs and PDF reports carry SHA-256 hashes; the IPFS
  vault is independently verifiable from the dashboard.

---

## 📁 Repository layout

```
Cerberus-Pi/
├── scripts/            cerberus_install.sh · cerberus_harden.sh · cerberus_start.sh
│                       engine_monitor.py · block_ip.sh · lib/common.sh
├── backend/            Django project (threats, scanner, logs, reports, engine,
│                       auth_audit, intelligence, api) + requirements + migrations
│   └── intelligence/   Phase 11 AI module (ml/ models + datasets/ seed data)
├── frontend/           React + Vite + Tailwind dashboard (7 pages incl. AI Intelligence)
├── config/             suricata.yaml · snort.lua · nginx · sysctl
├── systemd/            all cerberus-*.service units + target + sudoers
├── DEPLOYMENT.md       step-by-step Pi runbook
└── README.md           this file
```

---

## ✅ Status

| Component | Verified |
|-----------|----------|
| Backend (`manage.py check`) | ✅ 0 issues |
| Migrations (7 apps) | ✅ generate cleanly |
| Frontend (`npm run build`) | ✅ builds (2425 modules) |
| Shell scripts (`bash -n`) | ✅ clean |
| Python (`compileall`) | ✅ clean |
| Security validators | ✅ injection/abuse rejected (tested) |
| **AI module (Phase 11)** | ✅ 10 tests pass · SQLi `' OR 1=1--`→0.93 · XSS `<script>alert(1)</script>`→1.0 · benign ignored · <15 ms/event |

OS-level behaviour (engines, hardening, stealth, systemd, IPFS) and the DoS LSTM
(needs TensorFlow on ARM64) are validated on the Pi itself per the tutorial above.

> **Known on-device task:** Snort 3 is not apt-installable on Bookworm; build it
> from source (DAQ + Snort 3) so `/usr/local/bin/snort` exists before `start`.
> IPS/NFQueue mode ships disabled (passive IDS by default).

---

<div align="center">

**Cerberus Pi** · Yanova Solutions · INAPI Patent No. 240625

</div>
