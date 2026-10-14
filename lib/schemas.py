"""Shared data contracts for SentinelOps. Owned by P1: request changes via PR."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

AgentName = Literal[
    "orchestrator", "enrichment", "correlation",
    "severity", "playbook", "approval", "human", "end",
]

MAX_REVISION_ROUNDS = 3


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Alert(BaseModel):
    # accepts both our own field names and the seed-data names (host, description)
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    alert_id: str
    timestamp: str
    source: str
    rule: str
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_host: Optional[str] = Field(
        None, validation_alias=AliasChoices("dest_host", "host"))
    user: Optional[str] = None
    raw_log: str = Field(
        "", validation_alias=AliasChoices("raw_log", "description"))
    raw_severity: Optional[str] = None
    scenario: Optional[str] = None


# ---------- P2: Enrichment ----------
class Enrichment(BaseModel):
    ip_reputation: Literal["malicious", "suspicious", "clean", "unknown"] = "unknown"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    known_benign: bool = False       # e.g. internal IT scanner
    indicators: list[str] = []       # matched IOCs, tags, domains
    sources_used: list[str] = []
    sources_failed: list[str] = []   # shows fallback behaviour in the trace
    notes: str = ""


# ---------- P2: Correlation ----------
class Correlation(BaseModel):
    related_alert_ids: list[str] = []
    merged_into_existing: bool = False
    reasoning: str = ""


# ---------- P2: Severity ----------
class Severity(BaseModel):
    score: int = Field(0, ge=0, le=100)
    reasoning: str = ""
    needs_reenrichment: bool = False


# ---------- P3: Playbook + Approval ----------
ActionType = Literal["isolate_host", "block_ip", "disable_user", "reset_creds"]


class ProposedAction(BaseModel):
    action: ActionType
    target: str                      # host, IP or username
    params: dict[str, Any] = {}


class Proposal(BaseModel):
    round: int
    actions: list[ProposedAction]
    rationale: str = ""


class ApprovalDecision(BaseModel):
    round: int
    decision: Literal["approve", "modify", "reject"]
    reason: str
    constraints: list[str] = []      # feedback sent back to Playbook
    modified_actions: list[ProposedAction] = []   # used when decision == "modify"


# ---------- Shared incident record (the blackboard) ----------
class AuditEntry(BaseModel):
    ts: str = Field(default_factory=_now)
    agent: AgentName
    message: str


IncidentStatus = Literal[
    "open", "enriching", "correlating", "scoring", "proposing",
    "awaiting_approval", "contained", "auto_closed", "escalated_to_human", "error",
]


class Incident(BaseModel):
    incident_id: str
    alerts: list[Alert] = []
    enrichment: Optional[Enrichment] = None
    correlation: Optional[Correlation] = None
    severity: Optional[Severity] = None
    proposals: list[Proposal] = []
    decisions: list[ApprovalDecision] = []
    executed_actions: list[str] = []      # simulated only
    status: IncidentStatus = "open"

    # routing / control (Orchestrator reads and writes these)
    next_agent: Optional[AgentName] = None
    enrichment_attempts: int = 0
    revision_round: int = 0

    audit_trail: list[AuditEntry] = []

    def log(self, agent: AgentName, message: str) -> None:
        self.audit_trail.append(AuditEntry(agent=agent, message=message))


# ---------- Trace (written to traces/*.jsonl by lib/trace.py) ----------
class TraceEvent(BaseModel):
    ts: str = Field(default_factory=_now)
    incident_id: str
    from_agent: AgentName
    to_agent: AgentName
    event: Literal["handoff", "tool_call", "tool_error", "decision", "feedback", "escalation"]
    payload: dict[str, Any] = {}