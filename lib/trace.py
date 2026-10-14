"""JSONL execution trace: one line per agent handoff/decision. Owned by P1."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from lib.schemas import AgentName, TraceEvent


def _trace_path(incident_id: str) -> Path:
    d = Path(os.getenv("TRACE_DIR", "traces"))
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{incident_id}.jsonl"


def log_event(incident_id: str, from_agent: AgentName, to_agent: AgentName,
              event: str, payload: Optional[dict[str, Any]] = None) -> TraceEvent:
    ev = TraceEvent(incident_id=incident_id, from_agent=from_agent,
                    to_agent=to_agent, event=event, payload=payload or {})
    with open(_trace_path(incident_id), "a", encoding="utf-8") as f:
        f.write(ev.model_dump_json() + "\n")
    return ev


def read_trace(incident_id: str) -> list[TraceEvent]:
    p = _trace_path(incident_id)
    if not p.exists():
        return []
    return [TraceEvent.model_validate_json(line)
            for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]