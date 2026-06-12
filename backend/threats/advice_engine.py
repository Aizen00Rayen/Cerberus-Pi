"""
Phase 5.5 — AI Threat Advice Engine.

Rule-based remediation advice per threat category, with optional LLM enhancement
when LLM_PROVIDER is configured. The rule base is always authoritative and works
fully offline; the LLM only *adds* contextual colour and never blocks output.
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger("cerberus.advice")

# Canonical category → advice. Keys are matched case-insensitively as substrings
# against the Suricata/Snort category string, so "ET SCAN Nmap" matches "Port Scan"
# via the alias table below.
ADVICE_MAP: dict[str, str] = {
    "Port Scan": "Block the source IP at the firewall. Review and tighten inbound rules. "
                 "Enable port-scan detection thresholds in Suricata/Snort.",
    "Brute Force": "Enforce account lockout after repeated failures. Rotate exposed credentials. "
                   "Confirm fail2ban is jailing this source. Require key-based auth where possible.",
    "SQL Injection": "Patch and parameterise the affected web application. Enable a WAF rule set. "
                     "Audit database access logs for successful exfiltration.",
    "Malware C2": "Isolate the affected host from the network immediately. Capture volatile memory, "
                  "then run a full forensic scan. Block the C2 domain/IP everywhere.",
    "DNS Tunneling": "Block DNS over non-standard ports. Force internal clients through the resolver. "
                     "Alert on abnormal DNS query volume and long TXT records.",
    "DoS/DDoS": "Rate-limit the offending source. Confirm SYN cookies are enabled. "
                "Engage the upstream provider/ISP for scrubbing if volume is high.",
    "Exploit": "Identify the targeted CVE and patch the vulnerable service. Virtual-patch via IPS "
               "rule until the fix lands. Verify the host was not already compromised.",
    "Web Application Attack": "Review web server and app logs around this event. Deploy/enable WAF "
                              "signatures. Patch the framework/CMS to the latest version.",
    "Trojan": "Quarantine the host. Identify the persistence mechanism. Rebuild from known-good image "
              "rather than cleaning in place.",
    "Phishing": "Warn affected users, reset credentials, and block the phishing domain. Review mail "
                "gateway filtering.",
    "Policy Violation": "Review whether this traffic is sanctioned. Update acceptable-use policy and "
                        "egress filtering as needed.",
    "Reconnaissance": "Treat as a precursor to attack. Block the source, increase logging on targeted "
                      "hosts, and review exposed services.",
    "Credential Theft": "Force a credential rotation for impacted accounts. Enable MFA. Inspect for "
                        "lateral movement.",
}

# Aliases mapping common engine category strings onto canonical advice keys.
_ALIASES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"scan|nmap|portscan|sweep", re.I), "Port Scan"),
    (re.compile(r"brute|login|ssh.*fail|hydra|credential stuffing", re.I), "Brute Force"),
    (re.compile(r"sql.?inj|sqli", re.I), "SQL Injection"),
    (re.compile(r"\bc2\b|command.and.control|cnc|botnet", re.I), "Malware C2"),
    (re.compile(r"dns.?tunn|exfil.*dns", re.I), "DNS Tunneling"),
    (re.compile(r"ddos|dos|flood|amplif", re.I), "DoS/DDoS"),
    (re.compile(r"exploit|cve-|overflow|rce|deserial", re.I), "Exploit"),
    (re.compile(r"web.?app|xss|lfi|rfi|traversal|webattack", re.I), "Web Application Attack"),
    (re.compile(r"trojan|backdoor|implant", re.I), "Trojan"),
    (re.compile(r"phish", re.I), "Phishing"),
    (re.compile(r"recon|probe|enumerat", re.I), "Reconnaissance"),
    (re.compile(r"credential|password dump|mimikatz", re.I), "Credential Theft"),
    (re.compile(r"policy", re.I), "Policy Violation"),
]

_DEFAULT = ("Investigate the alert context and source reputation. If malicious, block the source IP, "
            "preserve logs for forensics, and confirm no host was compromised.")


def canonical_category(raw_category: str, signature: str = "") -> str:
    """Map a raw engine category/signature onto a canonical advice key."""
    haystack = f"{raw_category} {signature}"
    if raw_category in ADVICE_MAP:
        return raw_category
    for pattern, key in _ALIASES:
        if pattern.search(haystack):
            return key
    return ""


def rule_based_advice(category: str, signature: str = "") -> str:
    key = canonical_category(category, signature)
    return ADVICE_MAP.get(key, _DEFAULT)


def get_advice(category: str, signature: str = "", *, severity: str = "MEDIUM",
               src_ip: str | None = None) -> str:
    """
    Return remediation advice for a threat. Always returns rule-based advice;
    appends LLM context when configured and reachable.
    """
    base = rule_based_advice(category, signature)
    enhanced = _llm_enhance(base, category, signature, severity, src_ip)
    return enhanced or base


def _llm_enhance(base, category, signature, severity, src_ip) -> str | None:
    """Optional LLM enhancement. Never raises into the caller; returns None on any issue."""
    from django.conf import settings

    provider = (settings.LLM_PROVIDER or "").lower()
    if not provider:
        return None
    prompt = (
        "You are a SOC analyst. Given this IDS alert, give 2-3 concise, concrete "
        "remediation steps for a Raspberry Pi-based network sensor operator. "
        f"Severity={severity}. Category={category!r}. Signature={signature!r}. "
        f"Source IP={src_ip}. Baseline advice: {base}"
    )
    try:
        if provider == "openai":
            return _openai(prompt)
        if provider == "ollama":
            return _ollama(prompt)
    except Exception as exc:  # noqa: BLE001 — advice must never crash the parser
        logger.warning("LLM advice enhancement failed (%s): %s", provider, exc)
    return None


def _openai(prompt: str) -> str | None:
    import requests
    from django.conf import settings

    if not settings.OPENAI_API_KEY:
        return None
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 220,
            "temperature": 0.2,
        },
        timeout=12,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def _ollama(prompt: str) -> str | None:
    import requests
    from django.conf import settings

    resp = requests.post(
        f"{settings.OLLAMA_HOST}/api/generate",
        json={"model": "llama3.1", "prompt": prompt, "stream": False},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json().get("response", "").strip() or None
