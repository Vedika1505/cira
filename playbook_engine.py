"""
Playbook engine: loads YAML playbook definitions and executes their
steps against an incident/alert. Steps can template in alert fields
(e.g. "{host}", "{src_ip}") and are gated by an optional
`requires_approval` flag for impactful actions.

Playbook YAML shape:

    name: Ransomware Indicator Response
    match:
      alert_type: ransomware_indicator
      min_score: 70
    steps:
      - name: Notify SOC
        action: notify_slack
        params:
          message: "Ransomware indicator on {host} (user {user}) — score {score}"
      - name: Enrich file hash
        action: enrich_file_hash
        params:
          file_hash: "{file_hash}"
      - name: Isolate host
        action: isolate_host
        requires_approval: true
        params:
          host: "{host}"
"""
from __future__ import annotations

import glob
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml
from sqlmodel import Session

from app.connectors import ACTION_REGISTRY
from app.models import ActionLog, ActionStatus, Alert, Incident

logger = logging.getLogger("cira.playbook_engine")

PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "playbooks"


def load_playbooks() -> list[dict]:
    playbooks = []
    for path in sorted(glob.glob(str(PLAYBOOK_DIR / "*.yaml"))):
        with open(path, encoding="utf-8") as f:
            pb = yaml.safe_load(f)
            pb["_source_file"] = path
            playbooks.append(pb)
    return playbooks


def matches(playbook: dict, alert: Alert, score: int) -> bool:
    match = playbook.get("match", {})
    if "alert_type" in match and match["alert_type"] != alert.alert_type:
        return False
    if "min_score" in match and score < match["min_score"]:
        return False
    if "source" in match and match["source"] != alert.source:
        return False
    return True


def _template(value, context: dict):
    if isinstance(value, str):
        try:
            return value.format(**context)
        except (KeyError, IndexError):
            return value
    if isinstance(value, dict):
        return {k: _template(v, context) for k, v in value.items()}
    return value


async def run_playbook(
    session: Session,
    playbook: dict,
    incident: Incident,
    alert: Alert,
    score: int,
    auto_approve: bool = False,
) -> list[ActionLog]:
    """Execute every step of a playbook, logging each action."""
    context = {
        "host": alert.host or "",
        "user": alert.user or "",
        "src_ip": alert.src_ip or "",
        "dst_ip": alert.dst_ip or "",
        "file_hash": alert.file_hash or "",
        "score": score,
        "incident_id": incident.id,
        "alert_id": alert.id,
    }

    logs: list[ActionLog] = []
    for step in playbook.get("steps", []):
        action_type = step["action"]
        params = _template(step.get("params", {}), context)
        requires_approval = step.get("requires_approval", False)

        log = ActionLog(
            incident_id=incident.id,
            playbook_name=playbook.get("name", playbook["_source_file"]),
            step_name=step.get("name", action_type),
            action_type=action_type,
            params=params,
            requires_approval=requires_approval,
            status=ActionStatus.PENDING,
        )

        if requires_approval and not auto_approve:
            log.status = ActionStatus.SKIPPED_APPROVAL_REQUIRED
            log.result = "Awaiting human approval before execution."
            session.add(log)
            session.commit()
            session.refresh(log)
            logs.append(log)
            logger.info("Step '%s' requires approval, holding.", log.step_name)
            continue

        fn = ACTION_REGISTRY.get(action_type)
        log.status = ActionStatus.RUNNING
        log.started_at = datetime.utcnow()
        session.add(log)
        session.commit()

        if fn is None:
            log.status = ActionStatus.FAILED
            log.result = f"Unknown action_type '{action_type}' — no connector registered."
        else:
            try:
                result = await fn(**params)
                log.status = ActionStatus.SUCCESS
                log.result = str(result)
            except Exception as exc:  # noqa: BLE001 - log and continue playbook
                log.status = ActionStatus.FAILED
                log.result = f"Error: {exc}"
                logger.exception("Action %s failed", action_type)

        log.finished_at = datetime.utcnow()
        session.add(log)
        session.commit()
        session.refresh(log)
        logs.append(log)

    return logs


async def execute_approved_action(session: Session, action_log: ActionLog, approved_by: str) -> ActionLog:
    """Run a single previously-held action after a human approves it."""
    fn = ACTION_REGISTRY.get(action_log.action_type)
    action_log.approved_by = approved_by
    action_log.status = ActionStatus.RUNNING
    action_log.started_at = datetime.utcnow()
    session.add(action_log)
    session.commit()

    if fn is None:
        action_log.status = ActionStatus.FAILED
        action_log.result = f"Unknown action_type '{action_log.action_type}'"
    else:
        try:
            result = await fn(**action_log.params)
            action_log.status = ActionStatus.SUCCESS
            action_log.result = str(result)
        except Exception as exc:  # noqa: BLE001
            action_log.status = ActionStatus.FAILED
            action_log.result = f"Error: {exc}"

    action_log.finished_at = datetime.utcnow()
    session.add(action_log)
    session.commit()
    session.refresh(action_log)
    return action_log
