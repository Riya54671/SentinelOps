"""Severity Scoring Agent (P2): 0-100 score with reasoning; may request re-enrichment."""
from __future__ import annotations

import json

from pydantic import BaseModel

from agents._common import fail
from agents.orchestrator import MAX_ENRICH_ATTEMPTS
from lib import llm
from lib.schemas import Enrichment, Correlation, Incident, Severity
from lib.trace import log_event

CONFIDENCE_FLOOR = 0.6   # below this, the agent may ask for better evidence
MAX_DEVIATION = 25       # how far the LLM may move from the rule-based baseline

SYSTEM = """You are a SOC severity analyst. Score the incident 0-100
(0-30 low, 31-60 medium, 61-80 high, 81-100 critical) using the alert, threat-intel
enrichment and correlated alerts. A rule-based BASELINE score is provided; adjust it
only with a clear reason. Set needs_reenrichment=true ONLY if the threat-intel
evidence is too weak or incomplete to judge. Keep reasoning to 2-3 sentences."""


class _Judgement(BaseModel):
    score: int
    reasoning: str
    needs_reenrichment: bool = False


def baseline_score(enr: Enrichment, corr: Correlation) -> int:
    base = {"malicious": 60, "suspicious": 35, "unknown": 20, "clean": 5}[enr.ip_reputation]
    score = base + min(25, 6 * len(corr.related_alert_ids))
    if enr.known_benign:
        score = min(score, 10)
    return max(0, min(100, score))


def run(inc: Incident) -> Incident:
    try:
        alert, enr, corr = inc.alerts[0], inc.enrichment, inc.correlation
        base = baseline_score(enr, corr)
        can_retry = (enr.confidence < CONFIDENCE_FLOOR
                     and inc.enrichment_attempts < MAX_ENRICH_ATTEMPTS)

        try:
            j = llm.ask(SYSTEM, json.dumps({
                "alert": {"rule": alert.rule, "src_ip": alert.src_ip,
                          "host": alert.dest_host, "user": alert.user,
                          "log": alert.raw_log},
                "enrichment": enr.model_dump(),
                "related_alerts": len(corr.related_alert_ids),
                "BASELINE": base,
            }), _Judgement)
            score = max(base - MAX_DEVIATION, min(base + MAX_DEVIATION, j.score))
            reasoning = j.reasoning
            reenrich = j.needs_reenrichment and can_retry
        except Exception as e:
            score = base
            reasoning = (f"LLM unavailable ({type(e).__name__}); rule-based score: "
                         f"{enr.ip_reputation} IP + {len(corr.related_alert_ids)} related alerts.")
            reenrich = False

        if enr.known_benign:
            score = min(score, 10)
        score = max(0, min(100, score))

        inc.severity = Severity(score=score, reasoning=reasoning,
                                needs_reenrichment=reenrich)
        inc.log("severity", f"score {score}/100 (baseline {base}); "
                            f"re-enrichment requested: {reenrich}. {reasoning}")
        log_event(inc.incident_id, "severity", "orchestrator", "handoff",
                  {"score": score, "baseline": base, "needs_reenrichment": reenrich})
        return inc
    except Exception as e:
        return fail(inc, "severity", e)