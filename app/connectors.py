"""
Action connectors: each function is a pluggable interface to a real
security tool (EDR, firewall, IdP, ticketing, chat). They are stubbed
with clear TODOs — wire in your vendor's SDK/API here.

IMPORTANT: containment actions (isolate_host, disable_user, block_ip)
are destructive/impactful. In this scaffold they default to
`require_approval=True` in the sample playbooks, meaning the engine
will NOT execute them automatically — it logs a pending action and
waits for a human to approve via the API. You control this per-step
in the playbook YAML.
"""
from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger("cira.connectors")

# --- Notification connectors ------------------------------------------------

SLACK_WEBHOOK_URL = os.environ.get("CIRA_SLACK_WEBHOOK_URL", "")


async def notify_slack(message: str, **kwargs) -> str:
    if not SLACK_WEBHOOK_URL:
        logger.info("[DRY-RUN notify_slack] %s", message)
        return "dry-run: no CIRA_SLACK_WEBHOOK_URL configured"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(SLACK_WEBHOOK_URL, json={"text": message})
        resp.raise_for_status()
    return "sent"


async def notify_email(to: str, subject: str, body: str, **kwargs) -> str:
    # TODO: wire up SES / SendGrid / SMTP relay here.
    logger.info("[DRY-RUN notify_email] to=%s subject=%s body=%s", to, subject, body)
    return "dry-run: email connector not configured"


async def create_ticket(system: str, title: str, description: str, **kwargs) -> str:
    # TODO: wire up Jira / ServiceNow / Zendesk API here.
    logger.info("[DRY-RUN create_ticket] system=%s title=%s", system, title)
    return f"dry-run: would create ticket in {system}: {title}"


# --- Enrichment connectors ---------------------------------------------------

async def enrich_ip_reputation(ip: str, **kwargs) -> str:
    # TODO: wire up VirusTotal / AbuseIPDB / your TI platform here.
    logger.info("[DRY-RUN enrich_ip_reputation] ip=%s", ip)
    return f"dry-run: reputation lookup for {ip} not configured"


async def enrich_file_hash(file_hash: str, **kwargs) -> str:
    # TODO: wire up VirusTotal / internal sandbox API here.
    logger.info("[DRY-RUN enrich_file_hash] hash=%s", file_hash)
    return f"dry-run: hash lookup for {file_hash} not configured"


# --- Containment connectors (impactful — gate behind approval!) -------------

async def isolate_host(host: str, **kwargs) -> str:
    # TODO: wire up EDR API (CrowdStrike, SentinelOne, Defender for Endpoint...)
    logger.warning("[DRY-RUN isolate_host] host=%s", host)
    return f"dry-run: would isolate host {host} from network"


async def block_ip(ip: str, **kwargs) -> str:
    # TODO: wire up firewall/WAF API (Palo Alto, Cloudflare, AWS SG...)
    logger.warning("[DRY-RUN block_ip] ip=%s", ip)
    return f"dry-run: would block ip {ip} at perimeter firewall"


async def disable_user(user: str, **kwargs) -> str:
    # TODO: wire up IdP API (Okta, Azure AD / Entra, Google Workspace...)
    logger.warning("[DRY-RUN disable_user] user=%s", user)
    return f"dry-run: would disable account {user}"


async def reset_password(user: str, **kwargs) -> str:
    # TODO: wire up IdP API.
    logger.warning("[DRY-RUN reset_password] user=%s", user)
    return f"dry-run: would force password reset for {user}"


async def quarantine_file(host: str, file_hash: str, **kwargs) -> str:
    # TODO: wire up EDR API.
    logger.warning("[DRY-RUN quarantine_file] host=%s hash=%s", host, file_hash)
    return f"dry-run: would quarantine {file_hash} on {host}"


# Registry mapping playbook action_type strings -> callables.
# Extend this as you add connectors above.
ACTION_REGISTRY = {
    "notify_slack": notify_slack,
    "notify_email": notify_email,
    "create_ticket": create_ticket,
    "enrich_ip_reputation": enrich_ip_reputation,
    "enrich_file_hash": enrich_file_hash,
    "isolate_host": isolate_host,
    "block_ip": block_ip,
    "disable_user": disable_user,
    "reset_password": reset_password,
    "quarantine_file": quarantine_file,
}
