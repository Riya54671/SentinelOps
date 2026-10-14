"""Placeholder agents so the graph runs before P2/P3 merge. Delete once real."""
from lib.schemas import (ApprovalDecision, Correlation, Enrichment, Incident,
                         ProposedAction, Proposal, Severity)


def enrichment(inc: Incident) -> Incident:
    inc.enrichment = Enrichment(ip_reputation="malicious", confidence=0.9,
                                sources_used=["stub"])
    inc.log("enrichment", "stub enrichment")
    return inc


def correlation(inc: Incident) -> Incident:
    inc.correlation = Correlation(related_alert_ids=[a.alert_id for a in inc.alerts],
                                  reasoning="stub")
    inc.log("correlation", "stub correlation")
    return inc


def severity(inc: Incident) -> Incident:
    inc.severity = Severity(score=86, reasoning="stub")
    inc.log("severity", "stub severity 86")
    return inc


def playbook(inc: Incident) -> Incident:
    a = inc.alerts[0]
    n = len(inc.proposals) + 1
    if n == 1:
        actions = [ProposedAction(action="isolate_host", target=a.dest_host or "unknown")]
    else:
        actions = [ProposedAction(action="block_ip", target=a.src_ip or "0.0.0.0"),
                   ProposedAction(action="reset_creds", target=a.user or "unknown")]
    inc.proposals.append(Proposal(round=n, actions=actions, rationale="stub"))
    inc.log("playbook", f"stub proposal round {n}")
    return inc


def approval(inc: Incident) -> Incident:
    p = inc.proposals[-1]
    if p.round == 1:
        d = ApprovalDecision(round=1, decision="reject",
                             reason="Host runs payroll; isolation not allowed",
                             constraints=["do not isolate host", "prefer IP block"])
    else:
        d = ApprovalDecision(round=p.round, decision="approve", reason="Acceptable impact")
    inc.decisions.append(d)
    inc.log("approval", f"stub decision: {d.decision}")
    return inc


STUBS = {"enrichment": enrichment, "correlation": correlation,
         "severity": severity, "playbook": playbook, "approval": approval}