import requests
import random
import time

BASE = "http://localhost:8000"

TEMPLATES = [
    {"source": "crowdstrike", "alert_type": "ransomware_indicator", "host": "fin-ws-042", "user": "jsmith"},
    {"source": "okta", "alert_type": "brute_force", "user": "rpatel", "src_ip": "203.0.113.77"},
    {"source": "mail-gateway", "alert_type": "phishing_reported", "user": "aharris"},
    {"source": "crowdstrike", "alert_type": "malware_detected", "host": "hr-laptop-19", "user": "kwong"},
    {"source": "vpn-gateway", "alert_type": "impossible_travel", "user": "mgarcia", "src_ip": "198.51.100.23"},
    {"source": "edr", "alert_type": "privilege_escalation", "host": "dev-srv-03", "user": "tlee"},
]

print("Live feed started. Press Ctrl+C to stop.")
while True:
    alert = random.choice(TEMPLATES).copy()
    r = requests.post(f"{BASE}/alerts/ingest", json=alert)
    print(f"[sent] {alert['alert_type']} -> {r.status_code}")
    time.sleep(random.randint(5, 15))  # new alert every 5-15 seconds