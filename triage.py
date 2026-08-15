"""
Triage engine: turns a raw Alert into a severity score (0-100) using a
transparent, editable rule set. Swap in an ML model later if desired —
keep this function's signature (Alert -> (score, severity)) so the rest
of the system doesn't need to change.
"""
from __future__ import annotations

from app.models import Alert, Severity

# --- Editable rule weights -------------------------------------------------

ALERT_TYPE_BASE_SCORE = {
    "malware_detected": 60,
    "ransomware_indicator": 90,
    "brute_force": 40,
    "impossible_travel": 55,
    "phishing_reported": 30,
    "data_exfiltration": 85,
    "privilege_escalation": 70,
    "c2_beacon": 80,
    "unauthorized_access": 50,
}

CRITICAL_ASSET_HOSTS = {
    # Populate with hostnames/patterns for domain controllers, prod DBs, etc.
    # e.g. "dc01", "prod-db-01"
}

VIP_USERS = {
    # Populate with usernames of high-value targets (execs, admins)
}

KNOWN_BAD_IP_PREFIXES = (
    # Populate from your threat intel feed, or wire enrichment.py to a
    # live TI source instead of a static list.
)


def score_alert(alert: Alert) -> tuple[int, Severity]:
    score = ALERT_TYPE_BASE_SCORE.get(alert.alert_type, 25)

    if alert.host and any(h.lower() in alert.host.lower() for h in CRITICAL_ASSET_HOSTS):
        score += 20

    if alert.user and alert.user.lower() in {u.lower() for u in VIP_USERS}:
        score += 15

    if alert.src_ip and any(alert.src_ip.startswith(p) for p in KNOWN_BAD_IP_PREFIXES):
        score += 15

    if alert.severity_hint:
        hint = alert.severity_hint.lower()
        if hint in ("critical", "5"):
            score += 15
        elif hint in ("high", "4"):
            score += 10

    score = max(0, min(100, score))

    if score >= 85:
        severity = Severity.CRITICAL
    elif score >= 65:
        severity = Severity.HIGH
    elif score >= 40:
        severity = Severity.MEDIUM
    elif score >= 15:
        severity = Severity.LOW
    else:
        severity = Severity.INFO

    return score, severity
