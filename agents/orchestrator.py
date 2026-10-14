"""Orchestrator: decides which agent runs next. Owned by P1."""
from __future__ import annotations

import json

from pydantic import BaseModel

from lib import llm
from lib.schemas import AgentName, Incident, MAX_REVISION_ROUNDS
from lib.trace import log_event

MAX_ENRICH_ATTEMPTS = 2
LOW_CONFIDENCE = 0.4


class RouteDecision(BaseModel):
    next_agent: AgentName
    reasoning: str


SYSTEM = """You are the Orchestrator of a SOC alert-triage team. Pick the next
step from the ALLOWED list only. Guidance:
- 'end' right after enrichment means the alert is clearly benign (e.g. a known
  internal scanner): auto-close it.
- 'end' when no proposal exists yet means severity is too low to need action.
- Prefer 'enrichment' again only if evidence is weak (low confidence).
Reply with next_agent and one or two sentences of reasoning."""


def allowed_next(inc: Incident) -> list[AgentName]:
    """Hard guardrails: which steps are valid right now."""
    rejects = sum(1 for d in inc.decisions if d.decision == "reject")

    if inc.status == "error":
        return ["human"]
    if inc.enrichment is None:
        return ["enrichment"]

    if inc.correlation is None:
        opts: list[AgentName] = ["correlation"]
        if inc.enrichment.known_benign:
            opts.append("end")
        if (inc.enrichment.confidence < LOW_CONFIDENCE
                and inc.enrichment_attempts < MAX_ENRICH_ATTEMPTS):
            opts.append("enrichment")
        return opts

    if inc.severity is None:
        return ["severity"]
    if inc.severity.needs_reenrichment and inc.enrichment_attempts < MAX_ENRICH_ATTEMPTS:
        return ["enrichment"]

    if not inc.proposals:
        return ["playbook", "end"]
    if len(inc.decisions) < len(inc.proposals):
        return ["approval"]

    last = inc.decisions[-1].decision
    if last in ("approve", "modify"):
        return ["end"]
    # rejected
    return ["human"] if rejects >= MAX_REVISION_ROUNDS else ["playbook"]


def _summary(inc: Incident, allowed: list[str]) -> str:
    return json.dumps({
        "alerts": [{"rule": a.rule, "src_ip": a.src_ip, "host": a.dest_host}
                   for a in inc.alerts],
        "enrichment": inc.enrichment.model_dump() if inc.enrichment else None,
        "severity": inc.severity.model_dump() if inc.severity else None,
        "proposals_so_far": len(inc.proposals),
        "last_decision": inc.decisions[-1].model_dump() if inc.decisions else None,
        "ALLOWED": allowed,
    }, indent=2)


def _final_status(inc: Incident) -> str:
    if inc.decisions and inc.decisions[-1].decision in ("approve", "modify"):
        d = inc.decisions[-1]
        acts = d.modified_actions if d.decision == "modify" else inc.proposals[-1].actions
        inc.executed_actions = [f"{a.action} {a.target} (SIMULATED)" for a in acts]
        return "contained"
    return "auto_closed"


def run(inc: Incident) -> Incident:
    inc.revision_round = sum(1 for d in inc.decisions if d.decision == "reject")
    allowed = allowed_next(inc)

    if len(allowed) == 1:
        choice, why = allowed[0], "Only valid next step."
    else:
        try:
            d = llm.ask(SYSTEM, _summary(inc, allowed), RouteDecision)
            if d.next_agent in allowed:
                choice, why = d.next_agent, d.reasoning
            else:
                choice, why = allowed[0], f"LLM chose invalid '{d.next_agent}'; defaulted."
        except Exception as e:
            choice, why = allowed[0], f"LLM unavailable ({e}); defaulted."

    # side effects of the chosen route
    if choice == "enrichment":
        inc.enrichment_attempts += 1
        inc.status = "enriching"
        if inc.severity and inc.severity.needs_reenrichment:
            inc.severity = None          # force re-scoring after new evidence
    elif choice == "correlation":
        inc.status = "correlating"
    elif choice == "severity":
        inc.status = "scoring"
    elif choice == "playbook":
        inc.status = "proposing"
    elif choice == "approval":
        inc.status = "awaiting_approval"
    elif choice == "human":
        inc.status = "escalated_to_human" if inc.status != "error" else "error"
    elif choice == "end":
        inc.status = _final_status(inc)

    inc.next_agent = choice
    inc.log("orchestrator", f"-> {choice}: {why}")
    log_event(inc.incident_id, "orchestrator", choice,
              "escalation" if choice == "human" else "decision",
              {"allowed": allowed, "reasoning": why})
    return inc