"""Correlation Agent (P2): merge into an existing incident or open a new one."""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from agents._common import fail, store_row
from lib import llm
from lib.schemas import Correlation, Incident
from lib.trace import log_event
from tools import alert_store

DB_PATH = alert_store.DB_PATH
WINDOW_MINUTES = 120

SYSTEM = """You are a SOC correlation analyst. Given a NEW alert and CANDIDATE
earlier alerts that share a host, user or IP within a time window, decide which
candidates belong to the same attack. Only return alert_ids from the candidate
list. Explain briefly why they belong together or why not."""


class _Judgement(BaseModel):
    related_alert_ids: list[str] = []
    reasoning: str


def _ensure_seeded(db_path: Path) -> None:
    if not Path(db_path).exists():
        alert_store.load_seed_alerts(db_path=db_path)


def run(inc: Incident) -> Incident:
    try:
        alert = inc.alerts[0]
        _ensure_seeded(DB_PATH)

        try:
            candidates = alert_store.query_related(
                store_row(alert), window_minutes=WINDOW_MINUTES, db_path=DB_PATH)
        except Exception as e:  # e.g. unparsable timestamp
            candidates = []
            log_event(inc.incident_id, "correlation", "orchestrator", "tool_error",
                      {"error": f"store query failed: {e}"})

        log_event(inc.incident_id, "correlation", "orchestrator", "tool_call",
                  {"candidates": [c["alert_id"] for c in candidates]})

        valid = {c["alert_id"] for c in candidates}
        ids, reasoning = sorted(valid), ""

        if candidates:
            try:
                payload = {
                    "new_alert": {"rule": alert.rule, "host": alert.dest_host,
                                  "user": alert.user, "src_ip": alert.src_ip,
                                  "time": alert.timestamp, "log": alert.raw_log},
                    "candidates": [{k: c[k] for k in
                                    ("alert_id", "rule", "host", "user", "src_ip",
                                     "dest_ip", "timestamp", "description")}
                                   for c in candidates],
                }
                j = llm.ask(SYSTEM, json.dumps(payload), _Judgement)
                ids = [i for i in j.related_alert_ids if i in valid]
                reasoning = j.reasoning
            except Exception as e:
                reasoning = (f"LLM unavailable ({type(e).__name__}); treated all "
                             f"{len(ids)} entity/time matches as related.")
        else:
            reasoning = "No earlier alerts share a host, user or IP in the time window."

        inc.correlation = Correlation(
            related_alert_ids=ids,
            merged_into_existing=bool(ids),
            reasoning=reasoning,
        )
        alert_store.add_alert(store_row(alert), db_path=DB_PATH)

        action = f"merged with {len(ids)} related alerts" if ids else "opened as a new incident"
        inc.log("correlation", f"{action}. {reasoning}")
        log_event(inc.incident_id, "correlation", "orchestrator", "handoff",
                  {"related": ids, "merged_into_existing": bool(ids)})
        return inc
    except Exception as e:
        return fail(inc, "correlation", e)