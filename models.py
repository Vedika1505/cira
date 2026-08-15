"""
Data models for the Cyber Incident Response Automation (CIRA) system.

Everything is persisted via SQLModel (SQLite by default; swap the
DATABASE_URL env var for Postgres/MySQL in production).
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlmodel import SQLModel, Field, JSON, Column


def _uuid() -> str:
    return str(uuid.uuid4())


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class Alert(SQLModel, table=True):
    """Raw alert as received from a source system (SIEM, EDR, mail gateway...)."""

    id: str = Field(default_factory=_uuid, primary_key=True)
    received_at: datetime = Field(default_factory=datetime.utcnow)
    source: str  # e.g. "crowdstrike", "splunk", "manual"
    alert_type: str  # e.g. "malware_detected", "brute_force", "phishing_reported"
    raw_payload: dict = Field(default_factory=dict, sa_column=Column(JSON))

    # Extracted/normalized fields used by triage & playbook matching
    host: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    file_hash: Optional[str] = None
    severity_hint: Optional[str] = None  # severity as reported by the source, if any

    incident_id: Optional[str] = Field(default=None, foreign_key="incident.id")


class Incident(SQLModel, table=True):
    """A triaged, trackable case — may aggregate multiple related alerts."""

    id: str = Field(default_factory=_uuid, primary_key=True)
    title: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    score: int = 0  # computed triage score, 0-100
    summary: str = ""
    assignee: Optional[str] = None
    playbook_run_ids: list = Field(default_factory=list, sa_column=Column(JSON))


class ActionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED_APPROVAL_REQUIRED = "skipped_approval_required"


class ActionLog(SQLModel, table=True):
    """Audit trail: every automated (or approved manual) action taken."""

    id: str = Field(default_factory=_uuid, primary_key=True)
    incident_id: str = Field(foreign_key="incident.id")
    playbook_name: str
    step_name: str
    action_type: str  # e.g. "isolate_host", "block_ip", "notify_slack"
    params: dict = Field(default_factory=dict, sa_column=Column(JSON))
    status: ActionStatus = ActionStatus.PENDING
    result: Optional[str] = None
    requires_approval: bool = False
    approved_by: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
