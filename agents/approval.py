"""Business-Impact Approval Agent (P3): approve, modify, or reject the
latest Playbook proposal, with a reason and constraints that feed back
into the next Playbook round.

Contract: def run(incident: Incident) -> Incident. Never sets
next_agent or decides on escalation after MAX_REVISION_ROUNDS -- that
guardrail lives in agents/orchestrator.py's allowed_next(), which this
agent doesn't need to know about.

WHY this is a separate agent from Playbook: Playbook answers "what's
technically the right response?"; this agent answers "is doing that,
right now, worth the business disruption?" -- e.g. isolating a
critical finance DB mid-payroll-run might be technically correct and
still the wrong call. Splitting them keeps that business judgement in
exactly one place and keeps the CMDB/maintenance-window logic out of
Playbook entirely.
"""
from __future__ import annotations

import json

from pydantic import BaseModel

from agents._common import fail
from lib import llm
from lib.schemas import ApprovalDecision, Incident, ProposedAction
from lib.trace import log_event
from tools import cmdb
from tools.actions import is_high_impact

SYSTEM = """You are a business-impact reviewer for a SOC. Weigh the
proposed action(s) against the asset's criticality, business function
and maintenance window. Approve low-risk actions. Modify when a small
constraint (e.g. defer to the maintenance window) would make it safe.
Reject when the business impact is too high as proposed -- and give a
reason specific enough that the playbook agent can revise around it.
Keep your reason to 1-2 sentences."""

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

def _in_maintenance_window(asset, when):
    """True if `when` falls inside asset['maintenance_window'], e.g. 'Sun 02:00-04:00 IST'."""
    spec = (asset or {}).get("maintenance_window") or ""
    m = re.match(r"(\w{3})\s+(\d{2}):(\d{2})-(\d{2}):(\d{2})\s*(\w+)?", spec.strip())
    if not m:
        return False                      # no usable window -> treat as outside
    day, h1, m1, h2, m2, tz = m.groups()
    zone = ZoneInfo("Asia/Kolkata") if tz == "IST" else timezone.utc
    local = when.astimezone(zone)
    if local.weekday() != _DAYS.index(day.lower()):
        return False
    minutes = local.hour * 60 + local.minute
    return int(h1) * 60 + int(m1) <= minutes < int(h2) * 60 + int(m2)


class _Judgement(BaseModel):
    decision: str          # "approve" | "modify" | "reject"
    reason: str
    constraints: list[str] = []


def _fallback_decision(round_number: int, actions: list[ProposedAction],
                        record: dict | None) -> ApprovalDecision:
    """Deterministic fallback for when the LLM is unavailable. A
    critical asset + a high-impact action rejects (forces a revision);
    a high-impact action on a non-critical asset gets approved with a
    constraint; everything else is approved outright."""
    high_impact = [a for a in actions if is_high_impact(a, record)]

    if high_impact and record and record.get("criticality") == "critical":
        return ApprovalDecision(
            round=round_number,
            decision="reject",
            reason=(f"Fallback rule: action targets CRITICAL asset "
                    f"'{record['hostname']}'. Propose a less disruptive alternative."),
            constraints=["avoid isolate_host/disable_user on this asset",
                         "prefer block_ip or reset_creds"],
        )
    if high_impact:
        window = record["maintenance_window"] if record else "no known window"
        return ApprovalDecision(
            round=round_number,
            decision="modify",
            reason="Fallback rule: high-impact action approved with a timing constraint.",
            constraints=[f"prefer executing during maintenance window: {window}"],
            modified_actions=actions,
        )
    return ApprovalDecision(
        round=round_number,
        decision="approve",
        reason="Fallback rule: low business-impact action, no blocking constraints.",
    )


def run(inc: Incident) -> Incident:
    try:
        proposal = inc.proposals[-1]
        alert = inc.alerts[0]
        record = cmdb.lookup_host(alert.dest_host or "")

        payload = {
            "actions": [a.model_dump() for a in proposal.actions],
            "rationale": proposal.rationale,
            "cmdb": record,
            "severity": inc.severity.model_dump() if inc.severity else None,
            "round": proposal.round,
        }

        try:
            j = llm.ask(SYSTEM, json.dumps(payload), _Judgement)
            decision = ApprovalDecision(
                round=proposal.round,
                decision=j.decision,
                reason=j.reason,
                constraints=j.constraints,
                modified_actions=proposal.actions if j.decision == "modify" else [],
            )
        except Exception as e:
            decision = _fallback_decision(proposal.round, proposal.actions, record)
            decision.reason = f"LLM unavailable ({type(e).__name__}); {decision.reason}"
        ts = datetime.fromisoformat(str(alert.timestamp).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        decision = _enforce_policy(inc, decision, proposal, record, ts)

        inc.decisions.append(decision)
        inc.decisions.append(decision)
        inc.log("approval", f"Round {decision.round}: {decision.decision}. {decision.reason}")
        log_event(inc.incident_id, "approval", "orchestrator", "decision",
                  {"round": decision.round, "decision": decision.decision,
                   "reason": decision.reason})
        return inc
    except Exception as e:
        return fail(inc, "approval", e)

def _enforce_policy(inc, decision, proposal, asset,when):
    """Never isolate a critical asset outside its maintenance window."""
    risky = [a for a in proposal.actions
             if a.action == "isolate_host" and asset
             and asset.get("criticality") == "critical"
             and not _in_maintenance_window(asset,when)]
    if risky:
        safe = [a for a in proposal.actions if a not in risky]
        if safe:   # keep the safe actions -> real MODIFY
            decision.decision = "modify"
            decision.modified_actions = safe
            decision.constraints = [f"defer isolate_host on {risky[0].target} "
                                    f"to maintenance window ({asset['maintenance_window']})"]
        else:      # nothing safe left -> REJECT, send back to Playbook
            decision.decision = "reject"
            decision.modified_actions = []
            decision.constraints = ["do not isolate host", "prefer network-level IP block",
                                    "credential reset is acceptable"]
        decision.reason = (f"{risky[0].target} is critical ({asset['business_function']}); "
                           "isolation is blocked outside the maintenance window.")
    elif decision.decision == "modify" and decision.modified_actions == proposal.actions:
        decision.decision = "approve"   # LLM changed nothing, so it's really an approve
    return decision
