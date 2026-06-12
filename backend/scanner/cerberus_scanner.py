"""
Phase 4 — Cerberus multi-angle network scanner.

Wraps nmap (via python-nmap) and arp-scan. Each scan type maps to a concrete
command. Results are normalised into host dicts, risk-scored, and (optionally)
enriched with CVE data via the NVD API. The Celery tasks in tasks.py call these
functions and persist NetworkHost / ScanResult rows.

NOTE: scanning is an *active* operation and must run on the MANAGEMENT interface,
never the passive monitored eth0 (Constraint #2). The caller is responsible for
targeting the management subnet.
"""
from __future__ import annotations

import logging
import re
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger("cerberus.scanner")

# nmap arguments per scan type (Phase 4.1 table).
NMAP_ARGS = {
    "discovery": "-sn",
    "port": "-sS -sV",
    "os": "-O",
    "vuln": "-sV --script vuln",
    "service": "-sV --version-intensity 9",
    "stealth": "-sS -T2",
    "udp": "-sU --top-ports 100",
}


def _nmap():
    import nmap  # python-nmap
    return nmap.PortScanner()


def _resolve_localnet() -> str:
    """Best-effort: derive the local /24 CIDR of the primary outbound interface."""
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packets are sent; this just selects the primary source address.
        s.connect(("192.168.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    octets = ip.split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"


def run_nmap(scan_type: str, target: str) -> dict:
    """Run an nmap scan and return {ip: host_dict}."""
    args = NMAP_ARGS.get(scan_type, "-sV")
    if target == "localnet":
        target = _resolve_localnet()
    scanner = _nmap()
    logger.info("nmap %s %s", args, target)
    scanner.scan(hosts=target, arguments=args)
    hosts = {}
    for ip in scanner.all_hosts():
        node = scanner[ip]
        hosts[ip] = _host_from_nmap(ip, node)
    return hosts


def _host_from_nmap(ip: str, node) -> dict:
    ports = []
    for proto in node.all_protocols():
        for port, info in node[proto].items():
            if info.get("state") == "open":
                ports.append({
                    "port": port,
                    "proto": proto,
                    "service": info.get("name", ""),
                    "version": (f"{info.get('product','')} {info.get('version','')}").strip(),
                    "cpe": info.get("cpe", ""),
                })
    os_detected = ""
    if "osmatch" in node and node["osmatch"]:
        os_detected = node["osmatch"][0].get("name", "")
    return {
        "ip_address": ip,
        "mac_address": node["addresses"].get("mac", ""),
        "hostname": node.hostname() if hasattr(node, "hostname") else "",
        "os_detected": os_detected,
        "open_ports": ports,
        "vulnerabilities": _extract_vuln_scripts(node),
    }


def _extract_vuln_scripts(node) -> list[dict]:
    """Pull CVE ids out of nmap --script vuln output."""
    vulns = []
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}")
    for proto in node.all_protocols():
        for _port, info in node[proto].items():
            script = info.get("script", {})
            for name, output in script.items():
                for cve in set(cve_re.findall(output or "")):
                    vulns.append({"id": cve, "source": name, "cvss": None, "summary": ""})
    return vulns


def run_arp_scan(target: str = "--localnet") -> dict:
    """Layer-2 host discovery via arp-scan. Returns {ip: host_dict}."""
    cmd = ["arp-scan", target] if target != "--localnet" else ["arp-scan", "--localnet"]
    hosts = {}
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.error("arp-scan failed: %s", exc)
        return hosts
    line_re = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)$")
    for line in out.stdout.splitlines():
        m = line_re.match(line.strip())
        if m:
            ip, mac, vendor = m.groups()
            hosts[ip] = {
                "ip_address": ip, "mac_address": mac, "hostname": "",
                "os_detected": vendor.strip(), "open_ports": [], "vulnerabilities": [],
            }
    return hosts


def run_scan(scan_type: str, target: str) -> dict:
    """Dispatch to the right backend and return {ip: host_dict}."""
    # Defence in depth: never pass an unvalidated target to a subprocess, even
    # if a caller bypassed the serializer (e.g. a scheduled scan).
    from .validators import is_safe_target

    if not is_safe_target(target):
        raise ValueError(f"Unsafe scan target rejected: {target!r}")
    if scan_type == "arp":
        return run_arp_scan(target if target not in ("", "localnet") else "--localnet")
    return run_nmap(scan_type, target)


# --- Risk scoring -----------------------------------------------------------
# Heuristic 0..100. Open high-risk ports, count of open ports, OS age signals,
# and number/severity of known CVEs all contribute.
_HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 3389, 5900, 1433, 3306, 6379, 27017}


def risk_score(host: dict) -> int:
    score = 0
    ports = host.get("open_ports", [])
    score += min(len(ports) * 4, 30)
    for p in ports:
        if p.get("port") in _HIGH_RISK_PORTS:
            score += 8
    os_name = (host.get("os_detected") or "").lower()
    if any(tok in os_name for tok in ("windows xp", "windows 7", "windows server 2003",
                                      "windows server 2008", "android 4", "2.6.")):
        score += 20  # end-of-life / legacy OS
    vulns = host.get("vulnerabilities", [])
    for v in vulns:
        cvss = v.get("cvss")
        score += int(cvss * 2) if isinstance(cvss, (int, float)) else 6
    return max(0, min(score, 100))


def enrich_cve(vuln: dict, api_key: str = "") -> dict:
    """Look up a CVE's CVSS + summary via the NVD 2.0 API (best-effort)."""
    import requests

    cve_id = vuln.get("id")
    if not cve_id:
        return vuln
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id}, headers=headers, timeout=12,
        )
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        if items:
            cve = items[0]["cve"]
            descs = cve.get("descriptions", [])
            vuln["summary"] = next((d["value"] for d in descs if d["lang"] == "en"), "")
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    vuln["cvss"] = metrics[key][0]["cvssData"]["baseScore"]
                    break
    except Exception as exc:  # noqa: BLE001
        logger.warning("NVD lookup failed for %s: %s", cve_id, exc)
    return vuln


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
