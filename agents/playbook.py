"""Response Playbook Agent (P3): propose actions, revise using approval
feedback after a rejection.

Contract: def run(incident: Incident) -> Incident. Never sets
next_agent -- that's the Orchestrator's job (see agents/orchestrator.py).

WHY an LLM here rather than a fixed if/else: the right action depends
on reading the alert, severity reasoning and CMDB context together
(e.g. "critical finance host mid-transaction" should favor block_ip/
reset_creds over isolate_host) -- that's open-ended judgement, not a
lookup table. The LLM call is wrapped in a rule-based fallback
(_fallback_actions) so a dead API key never stops the demo, matching
how severity.py and correlation.py handle LLM failures.
"""
from __future__ import annotations

import json

from pydantic import BaseModel

from agents._common import fail
from lib import llm
from lib.schemas import Incident, ProposedAction, Proposal
from lib.trace import log_event
from tools import cmdb
from tools.actions import catalog_description

SYSTEM = """You are a SOC response-playbook analyst. Given the incident
below, propose 1-2 actions using ONLY the action catalog provided.
If this is a revision after a rejection, address the reviewer's
feedback directly rather than repeating the rejected proposal.
Keep your rationale to 1-2 sentences."""


class _Judgement(BaseModel):
    actions: list[ProposedAction]
    rationale: str


def _fallback_actions(inc: Incident) -> list[ProposedAction]:
    """Deterministic fallback used when the LLM is unavailable. Mirrors
    the kind of simple rule a human on-call analyst would apply from
    the alert fields alone, so the demo never hard-crashes over a dead
    API key (task E: 'no hard crash').

    After a rejection, a disruptive first attempt (isolate_host /
    disable_user) is revised toward the surgical alternatives
    (block_ip + reset_creds) rather than resubmitted unchanged -- that's
    what lets the rejection loop actually converge instead of rejecting
    the same proposal three times and escalating every time."""
    alert = inc.alerts[0]
    last_decision = inc.decisions[-1] if inc.decisions else None

    if last_decision and last_decision.decision == "reject":
        revised = []
        if alert.src_ip:
            revised.append(ProposedAction(action="block_ip", target=alert.src_ip))
        if alert.user:
            revised.append(ProposedAction(action="reset_creds", target=alert.user))
        if revised:
            return revised
        # no IP/user to fall back on -- nothing less disruptive to try

    if alert.user and inc.severity and inc.severity.score >= 60:
        return [ProposedAction(action="disable_user", target=alert.user)]
    if alert.dest_host:
        return [ProposedAction(action="isolate_host", target=alert.dest_host)]
    if alert.src_ip:
        return [ProposedAction(action="block_ip", target=alert.src_ip)]
    return [ProposedAction(action="isolate_host", target="unknown-host")]


def run(inc: Incident) -> Incident:
    try:
        alert = inc.alerts[0]
        round_number = len(inc.proposals) + 1
        last_decision = inc.decisions[-1] if inc.decisions else None
        feedback = last_decision.reason if (last_decision and last_decision.decision == "reject") else None
        constraints = last_decision.constraints if last_decision else []

        record = cmdb.lookup_host(alert.dest_host or "")

        payload = {
            "alert": {"rule": alert.rule, "src_ip": alert.src_ip,
                      "host": alert.dest_host, "user": alert.user,
                      "log": alert.raw_log},
            "severity": inc.severity.model_dump() if inc.severity else None,
            "cmdb": record,
            "action_catalog": catalog_description(),
            "previous_rejection_feedback": feedback,
            "constraints_from_reviewer": constraints,
            "round": round_number,
        }

        try:
            j = llm.ask(SYSTEM, json.dumps(payload), _Judgement)
            actions, rationale = j.actions, j.rationale
        except Exception as e:
            actions = _fallback_actions(inc)
            rationale = (f"LLM unavailable ({type(e).__name__}); used rule-based "
                         f"fallback based on alert fields.")

        proposal = Proposal(round=round_number, actions=actions, rationale=rationale)
        inc.proposals.append(proposal)

        summary = ", ".join(f"{a.action} {a.target}" for a in actions)
        inc.log("playbook", f"Round {round_number} proposal: {summary}. {rationale}")
        log_event(inc.incident_id, "playbook", "orchestrator", "handoff",
                  {"round": round_number, "actions": [a.model_dump() for a in actions]})
        return inc
    except Exception as e:
        return fail(inc, "playbook", e)
