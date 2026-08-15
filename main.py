"""
CIRA — Cyber Incident Response Automation System

Run with:
    uvicorn app.main:app --reload --port 8000

Endpoints:
    POST /alerts/ingest          Submit a raw alert (from SIEM/EDR/manual)
    GET  /incidents              List incidents
    GET  /incidents/{id}         Incident detail incl. alerts & action log
    POST /incidents/{id}/status  Update incident status
    GET  /actions/pending        List actions awaiting human approval
    POST /actions/{id}/approve   Approve & execute a held action
    POST /actions/{id}/reject    Reject a held action
    GET  /playbooks              List loaded playbooks
    GET  /                       Simple HTML dashboard
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from app.database import get_session, init_db
from app.models import ActionLog, ActionStatus, Alert, Incident, IncidentStatus
from app.playbook_engine import load_playbooks, matches, run_playbook, execute_approved_action
from app.triage import score_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cira.main")

app = FastAPI(title="CIRA - Cyber Incident Response Automation")


@app.on_event("startup")
def on_startup():
    init_db()
    pbs = load_playbooks()
    logger.info("Loaded %d playbooks: %s", len(pbs), [p.get("name") for p in pbs])


# --- Schemas -----------------------------------------------------------------

class AlertIn(BaseModel):
    source: str
    alert_type: str
    host: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    file_hash: Optional[str] = None
    severity_hint: Optional[str] = None
    raw_payload: dict = {}


class StatusUpdate(BaseModel):
    status: IncidentStatus
    assignee: Optional[str] = None


class ApprovalIn(BaseModel):
    approved_by: str


# --- Ingestion & orchestration -------------------------------------------------

@app.post("/alerts/ingest")
async def ingest_alert(payload: AlertIn, session: Session = Depends(get_session)):
    alert = Alert(
        source=payload.source,
        alert_type=payload.alert_type,
        host=payload.host,
        user=payload.user,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        file_hash=payload.file_hash,
        severity_hint=payload.severity_hint,
        raw_payload=payload.raw_payload,
    )
    session.add(alert)
    session.commit()
    session.refresh(alert)

    score, severity = score_alert(alert)

    incident = Incident(
        title=f"{payload.alert_type.replace('_', ' ').title()} — {payload.host or payload.user or payload.src_ip or 'unknown asset'}",
        severity=severity,
        status=IncidentStatus.TRIAGED,
        score=score,
        summary=f"Auto-triaged from alert {alert.id} (source={payload.source}).",
    )
    session.add(incident)
    session.commit()
    session.refresh(incident)

    alert.incident_id = incident.id
    session.add(alert)
    session.commit()

    matched_playbooks = [pb for pb in load_playbooks() if matches(pb, alert, score)]
    all_action_logs = []
    for pb in matched_playbooks:
        logs = await run_playbook(session, pb, incident, alert, score)
        all_action_logs.extend(logs)
        incident.playbook_run_ids = incident.playbook_run_ids + [pb.get("name")]

    session.add(incident)
    session.commit()
    session.refresh(incident)

    return {
        "alert_id": alert.id,
        "incident_id": incident.id,
        "score": score,
        "severity": severity,
        "matched_playbooks": [pb.get("name") for pb in matched_playbooks],
        "actions_taken": [
            {"step": a.step_name, "action": a.action_type, "status": a.status, "result": a.result}
            for a in all_action_logs
        ],
    }


# --- Incidents -----------------------------------------------------------------

@app.get("/incidents")
def list_incidents(session: Session = Depends(get_session), status: Optional[IncidentStatus] = None):
    stmt = select(Incident).order_by(Incident.created_at.desc())
    if status:
        stmt = stmt.where(Incident.status == status)
    return session.exec(stmt).all()


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    alerts = session.exec(select(Alert).where(Alert.incident_id == incident_id)).all()
    actions = session.exec(select(ActionLog).where(ActionLog.incident_id == incident_id)).all()
    return {"incident": incident, "alerts": alerts, "actions": actions}


@app.post("/incidents/{incident_id}/status")
def update_status(incident_id: str, payload: StatusUpdate, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    incident.status = payload.status
    if payload.assignee:
        incident.assignee = payload.assignee
    incident.updated_at = datetime.utcnow()
    session.add(incident)
    session.commit()
    session.refresh(incident)
    return incident


# --- Human-in-the-loop approvals ------------------------------------------------

@app.get("/actions/pending")
def list_pending_actions(session: Session = Depends(get_session)):
    stmt = select(ActionLog).where(ActionLog.status == ActionStatus.SKIPPED_APPROVAL_REQUIRED)
    return session.exec(stmt).all()


@app.post("/actions/{action_id}/approve")
async def approve_action(action_id: str, payload: ApprovalIn, session: Session = Depends(get_session)):
    action = session.get(ActionLog, action_id)
    if not action:
        raise HTTPException(404, "Action not found")
    if action.status != ActionStatus.SKIPPED_APPROVAL_REQUIRED:
        raise HTTPException(400, f"Action is not pending approval (status={action.status})")
    return await execute_approved_action(session, action, payload.approved_by)


@app.post("/actions/{action_id}/reject")
def reject_action(action_id: str, payload: ApprovalIn, session: Session = Depends(get_session)):
    action = session.get(ActionLog, action_id)
    if not action:
        raise HTTPException(404, "Action not found")
    action.status = ActionStatus.FAILED
    action.approved_by = payload.approved_by
    action.result = "Rejected by human reviewer."
    session.add(action)
    session.commit()
    session.refresh(action)
    return action


# --- Playbooks -----------------------------------------------------------------

@app.get("/playbooks")
def list_playbooks():
    return [
        {"name": pb.get("name"), "description": pb.get("description"), "match": pb.get("match"), "steps": [s.get("name") for s in pb.get("steps", [])]}
        for pb in load_playbooks()
    ]


# --- Minimal dashboard -----------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(session: Session = Depends(get_session)):
    incidents = session.exec(select(Incident).order_by(Incident.created_at.desc()).limit(50)).all()
    pending = session.exec(select(ActionLog).where(ActionLog.status == ActionStatus.SKIPPED_APPROVAL_REQUIRED)).all()

    rows = "".join(
        f"<tr><td>{i.id[:8]}</td><td>{i.title}</td>"
        f"<td><span class='badge {i.severity}'>{i.severity}</span></td>"
        f"<td>{i.score}</td><td>{i.status}</td><td>{i.created_at:%Y-%m-%d %H:%M}</td></tr>"
        for i in incidents
    )
    pending_rows = "".join(
        f"<tr><td>{a.id[:8]}</td><td>{a.incident_id[:8]}</td><td>{a.playbook_name}</td>"
        f"<td>{a.step_name}</td><td>{a.action_type}</td><td><code>{a.params}</code></td></tr>"
        for a in pending
    )

    return f"""
    <html>
    <head>
        <title>CIRA Dashboard</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; margin: 2rem; background: #0b0e14; color: #e6e6e6; }}
            h1, h2 {{ font-weight: 600; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 2rem; }}
            th, td {{ text-align: left; padding: 0.5rem; border-bottom: 1px solid #2a2f3a; font-size: 0.9rem; }}
            th {{ color: #9aa4b2; text-transform: uppercase; font-size: 0.75rem; }}
            .badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; }}
            .critical {{ background: #7f1d1d; }}
            .high {{ background: #9a3412; }}
            .medium {{ background: #854d0e; }}
            .low {{ background: #365314; }}
            .info {{ background: #1e3a5f; }}
            .panel {{ background: #141821; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }}
            code {{ font-size: 0.75rem; color: #9aa4b2; }}
        </style>
    </head>
    <body>
        <h1>🛡️ CIRA — Incident Response Dashboard</h1>

        <div class="panel">
            <h2>Pending Approvals ({len(pending)})</h2>
            <table>
                <tr><th>Action ID</th><th>Incident</th><th>Playbook</th><th>Step</th><th>Action Type</th><th>Params</th></tr>
                {pending_rows or "<tr><td colspan=6>None pending</td></tr>"}
            </table>
            <p><code>POST /actions/{{id}}/approve  {{"approved_by": "you@company.com"}}</code></p>
        </div>

        <div class="panel">
            <h2>Recent Incidents ({len(incidents)})</h2>
            <table>
                <tr><th>ID</th><th>Title</th><th>Severity</th><th>Score</th><th>Status</th><th>Created</th></tr>
                {rows or "<tr><td colspan=6>No incidents yet — POST to /alerts/ingest</td></tr>"}
            </table>
        </div>

        <p style="color:#9aa4b2;">API docs at <a href="/docs" style="color:#60a5fa;">/docs</a></p>
    </body>
    </html>
    """
