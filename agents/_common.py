"""Shared helpers for the P2 agents."""
from __future__ import annotations

from lib.schemas import AgentName, Alert, Incident
from lib.trace import log_event


def fail(inc: Incident, agent: AgentName, exc: Exception) -> Incident:
    """One-agent failure: mark the incident as errored so the Orchestrator
    escalates to a human instead of crashing the graph."""
    inc.status = "error"
    inc.log(agent, f"FAILED: {type(exc).__name__}: {exc}")
    log_event(inc.incident_id, agent, "orchestrator", "tool_error",
              {"error": f"{type(exc).__name__}: {exc}"})
    return inc


def store_row(alert: Alert) -> dict:
    """Convert a schema Alert into a row for tools.alert_store."""
    return {
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp,
        "source": alert.source,
        "rule": alert.rule,
        "host": alert.dest_host or "",
        "user": alert.user or "",
        "src_ip": alert.src_ip or "",
        "dest_ip": "",
        "description": alert.raw_log,
        "raw_severity": "",
    }