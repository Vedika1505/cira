"""
Simulates alert ingestion directly against the FastAPI app (in-process,
via TestClient) so you can see the full flow -- triage, playbook match,
auto-actions, held approvals -- without standing up a server.

Run:
    python -m tests.simulate
"""
import json
from fastapi.testclient import TestClient

from app.main import app


def send(client, alert):
    r = client.post("/alerts/ingest", json=alert)
    print(f"\n=== {alert['alert_type']} ===")
    print(json.dumps(r.json(), indent=2, default=str))
    return r.json()


def main():
    with TestClient(app) as client:
        send(client, {
            "source": "crowdstrike",
            "alert_type": "ransomware_indicator",
            "host": "fin-ws-042",
            "user": "jsmith",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        })

        send(client, {
            "source": "okta",
            "alert_type": "brute_force",
            "user": "jsmith",
            "src_ip": "203.0.113.77",
            "severity_hint": "high",
        })

        send(client, {
            "source": "mail-gateway",
            "alert_type": "phishing_reported",
            "user": "aharris",
        })

        print("\n=== Pending approvals ===")
        print(json.dumps(client.get("/actions/pending").json(), indent=2, default=str))

        print("\n=== Incident list ===")
        print(json.dumps(client.get("/incidents").json(), indent=2, default=str))


if __name__ == "__main__":
    main()
