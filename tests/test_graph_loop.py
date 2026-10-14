from agents import orchestrator
from lib import graph
from lib.schemas import Alert, ApprovalDecision, Incident, Proposal, ProposedAction


def _alert():
    return Alert(alert_id="A-1", timestamp="2026-10-11T09:14:22Z", source="firewall",
                 rule="Multiple failed SSH logins", src_ip="185.220.101.45",
                 dest_host="payroll-srv-01", user="svc_payroll")


def test_reject_revise_approve(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))
    monkeypatch.setattr(
        orchestrator.llm, "ask",
        lambda system, user, schema, **kw: schema(next_agent="playbook", reasoning="test"))

    inc = graph.run_incident(_alert(), incident_id="INC-TEST")

    assert inc.status == "contained"
    assert len(inc.proposals) == 2
    assert inc.decisions[0].decision == "reject"
    assert inc.decisions[1].decision == "approve"
    assert (tmp_path / "INC-TEST.jsonl").exists()


def test_escalates_after_max_rejections():
    inc = Incident(incident_id="X", alerts=[_alert()])
    from lib.schemas import Correlation, Enrichment, Severity
    inc.enrichment = Enrichment(confidence=0.9)
    inc.correlation = Correlation()
    inc.severity = Severity(score=90)
    for r in (1, 2, 3):
        inc.proposals.append(Proposal(round=r, actions=[
            ProposedAction(action="isolate_host", target="h")]))
        inc.decisions.append(ApprovalDecision(round=r, decision="reject", reason="no"))
    assert orchestrator.allowed_next(inc) == ["human"]