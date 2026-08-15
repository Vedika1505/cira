# CIRA — Cyber Incident Response Automation System

A lightweight SOAR-style automation platform: ingest alerts from your
security tools, auto-triage them, and run YAML-defined response
playbooks — with human approval gates on any destructive/impactful
action (host isolation, account disable, IP block, etc.).

## Architecture

```
 SIEM / EDR / Mail   --POST-->   /alerts/ingest
 Gateway / Manual                     |
                                       v
                              Triage Engine (triage.py)
                              -> score 0-100, severity
                                       |
                                       v
                              Incident created/updated
                                       |
                                       v
                              Playbook Engine matches
                              YAML playbooks (playbooks/*.yaml)
                                       |
                     +-----------------+------------------+
                     v                                    v
          Low-impact actions run              Impactful actions HELD
          automatically (notify,               (isolate_host, block_ip,
          enrich, ticket)                       disable_user, ...)
                     |                                    |
                     v                                    v
              Action logged (audit trail)      Analyst reviews via
                                                /actions/pending and
                                                POST /actions/{id}/approve
```

**Design principle:** automation should accelerate triage/enrichment/
notification (low blast radius) while keeping a human in the loop for
anything that can disrupt a user or system. Every playbook step can set
`requires_approval: true` to enforce this — the ransomware and
brute-force sample playbooks demonstrate both patterns.

## Project layout

```
app/
  main.py             FastAPI app: ingestion, incidents, approvals, dashboard
  models.py           SQLModel tables: Alert, Incident, ActionLog
  database.py         DB engine/session (SQLite by default)
  triage.py           Editable scoring rules -> severity
  connectors.py       Pluggable actions (Slack, EDR, firewall, IdP...) — STUBBED
  playbook_engine.py  Loads YAML playbooks, executes/holds steps
playbooks/
  ransomware_indicator.yaml
  brute_force.yaml
  phishing_reported.yaml
tests/
  simulate.py         End-to-end demo without needing a running server
```

## Quickstart

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open **http://localhost:8000** for the dashboard, or **/docs** for the
interactive API.

Send a test alert:

```bash
curl -X POST http://localhost:8000/alerts/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "crowdstrike",
    "alert_type": "ransomware_indicator",
    "host": "fin-ws-042",
    "user": "jsmith",
    "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }'
```

Or run the built-in simulation (no server needed):

```bash
python -m tests.simulate
```

## Wiring in your real tools

Every action in `app/connectors.py` is a stub that logs a "dry-run"
message. To go live:

1. Add your vendor SDK/API client (e.g. CrowdStrike Falcon API,
   Okta API, Palo Alto/Cloudflare API) to `requirements.txt`.
2. Replace the `TODO` inside the relevant function in `connectors.py`
   with a real API call. Keep the function signature the same (it's
   called by name from `ACTION_REGISTRY` with `**params` from your
   playbook YAML).
3. Set required secrets via environment variables (see `.env.example`)
   — never hardcode credentials.

**Approval gate:** any connector you consider destructive should stay
behind `requires_approval: true` in the playbook YAML. The engine will
create a `PENDING`/`SKIPPED_APPROVAL_REQUIRED` ActionLog and wait for
a call to `POST /actions/{id}/approve` from an authenticated analyst
before invoking it. You should add real authentication/RBAC to that
endpoint before production use (see "Hardening" below).

## Writing a new playbook

Drop a new YAML file into `playbooks/`. It's picked up automatically
(reloaded on each ingest — no restart needed):

```yaml
name: Data Exfiltration Response
match:
  alert_type: data_exfiltration
  min_score: 60
steps:
  - name: Notify SOC
    action: notify_slack
    params:
      message: "Possible exfil on {host}, user {user}, score {score}"
  - name: Isolate host
    action: isolate_host
    requires_approval: true
    params:
      host: "{host}"
```

Available template variables in `params`: `{host}`, `{user}`,
`{src_ip}`, `{dst_ip}`, `{file_hash}`, `{score}`, `{incident_id}`,
`{alert_id}`.

Match conditions support `alert_type`, `min_score`, and `source`.

## Triage scoring

`app/triage.py` holds a transparent rule-based scorer:
base score by `alert_type`, boosted for critical assets / VIP users /
known-bad IPs / high source severity. Edit the dictionaries at the top
of the file for your environment (critical hostnames, VIP usernames,
TI-fed bad IP prefixes). Swap in an ML model later by keeping the same
`score_alert(alert) -> (score, severity)` signature.

## Data model

- **Alert** — raw normalized event from a source system
- **Incident** — the trackable case (one or more alerts can roll up
  into it in a future enhancement — the schema already supports
  `alert.incident_id`)
- **ActionLog** — full audit trail of every automated/approved action,
  including who approved it and the result

## Hardening before production use

This is a functional scaffold, not a production-hardened system. Before
deploying against real infrastructure:

- **Auth**: add authentication (OAuth2/OIDC, API keys) to all endpoints,
  especially `/alerts/ingest` (so anyone can't fabricate incidents) and
  `/actions/*/approve` (so approval is tied to a verified identity, not
  just a free-text `approved_by` string).
- **RBAC**: restrict who can approve destructive actions.
- **Idempotency**: add dedup logic so replayed/duplicate alerts from a
  flaky SIEM connector don't spawn duplicate incidents or re-run
  playbooks.
- **Rate limiting / backpressure** on the ingestion endpoint.
- **Database**: move off SQLite to Postgres for concurrent writes.
- **Secrets**: use a secrets manager (Vault, AWS Secrets Manager) rather
  than plain environment variables for connector credentials.
- **Testing**: add contract tests for each connector against a sandbox
  tenant of the relevant vendor before trusting it against production.
- **Rollback plan**: for every containment action, define and test the
  corresponding reversal (un-isolate host, unblock IP, re-enable user).
