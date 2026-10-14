"""Alert Enrichment Agent (P2): threat-intel lookup with fallback + confidence."""
from __future__ import annotations

import json

from pydantic import BaseModel

from agents._common import fail
from lib import llm
from lib.schemas import Enrichment, Incident
from lib.trace import log_event
from tools import threat_intel

BENIGN_TAGS = {"approved-scanner", "internal", "benign"}

SYSTEM = """You are a SOC enrichment analyst. In 1-2 sentences, summarise what the
threat-intel evidence says about the source IP of this alert. Mention if sources
failed or if evidence is weak. Do not invent facts."""


class _Notes(BaseModel):
    notes: str


def _reputation(score: int, malicious: bool) -> str:
    if malicious:
        return "malicious" if score >= 70 else "suspicious"
    return "suspicious" if score >= 30 else "clean"


def _notes(rule: str, ip: str, intel: dict, rep: str) -> str:
    try:
        out = llm.ask(SYSTEM, json.dumps({"rule": rule, "ip": ip, "intel": intel}), _Notes)
        return out.notes
    except Exception:
        return (f"{ip} rated {rep} (score {intel['score']}). "
                f"Used: {', '.join(intel['sources_used']) or 'none'}; "
                f"failed: {len(intel['sources_failed'])}.")


def run(inc: Incident) -> Incident:
    try:
        alert = inc.alerts[0]
        ip = alert.src_ip

        if not ip:
            inc.enrichment = Enrichment(
                ip_reputation="unknown", confidence=0.2,
                notes="Alert has no source IP, so there is nothing to look up.")
            inc.log("enrichment", "no source IP; confidence 0.2")
            log_event(inc.incident_id, "enrichment", "orchestrator", "handoff",
                      {"confidence": 0.2, "reason": "no_src_ip"})
            return inc

        intel = threat_intel.lookup_ip(ip)
        log_event(inc.incident_id, "enrichment", "orchestrator", "tool_call",
                  {"ip": ip, "sources_used": intel["sources_used"],
                   "fallback_used": intel["fallback_used"]})
        for failure in intel["sources_failed"]:
            log_event(inc.incident_id, "enrichment", "orchestrator", "tool_error",
                      {"source_error": failure})

        malicious = bool(intel["malicious"])
        rep = _reputation(intel["score"], malicious)
        known_benign = bool(BENIGN_TAGS & set(intel["tags"])) and not malicious

        inc.enrichment = Enrichment(
            ip_reputation=rep,
            confidence=float(intel["confidence"]),
            known_benign=known_benign,
            indicators=list(intel["tags"]) + [f"score:{intel['score']}"],
            sources_used=list(intel["sources_used"]),
            sources_failed=list(intel["sources_failed"]),
            notes=_notes(alert.rule, ip, intel, rep),
        )
        inc.log("enrichment",
                f"{ip}: {rep}, confidence {inc.enrichment.confidence}, "
                f"known_benign={known_benign}, attempt {inc.enrichment_attempts}")
        log_event(inc.incident_id, "enrichment", "orchestrator", "handoff",
                  {"reputation": rep, "confidence": inc.enrichment.confidence,
                   "known_benign": known_benign})
        return inc
    except Exception as e:
        return fail(inc, "enrichment", e)