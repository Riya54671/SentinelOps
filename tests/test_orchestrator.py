from agents import orchestrator
from lib.schemas import (Alert, ApprovalDecision, Correlation, Enrichment,
                         Incident, Proposal, ProposedAction, Severity)


def _alert():
    return Alert(alert_id="A-1", timestamp="2026-10-11T09:14:22Z", source="firewall",
                 rule="Multiple failed SSH logins", src_ip="185.220.101.45",
                 dest_host="payroll-srv-01", user="svc_payroll")


def _inc():
    return Incident(incident_id="INC-T", alerts=[_alert()])


def _fake_llm(choice):
    return lambda system, user, schema, **kw: schema(next_agent=choice, reasoning="test")


def test_new_incident_goes_to_enrichment_without_llm(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))
    inc = orchestrator.run(_inc())
    assert inc.next_agent == "enrichment"
    assert inc.enrichment_attempts == 1


def test_known_benign_allows_auto_close(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))
    monkeypatch.setattr(orchestrator.llm, "ask", _fake_llm("end"))
    inc = _inc()
    inc.enrichment = Enrichment(known_benign=True, confidence=0.9)
    assert "end" in orchestrator.allowed_next(inc)
    inc = orchestrator.run(inc)
    assert inc.next_agent == "end"
    assert inc.status == "auto_closed"


def test_low_confidence_allows_reenrichment():
    inc = _inc()
    inc.enrichment = Enrichment(confidence=0.2)
    inc.enrichment_attempts = 1
    assert "enrichment" in orchestrator.allowed_next(inc)


def test_reenrichment_blocked_after_max_attempts():
    inc = _inc()
    inc.enrichment = Enrichment(confidence=0.2)
    inc.enrichment_attempts = orchestrator.MAX_ENRICH_ATTEMPTS
    assert "enrichment" not in orchestrator.allowed_next(inc)


def test_severity_can_request_reenrichment():
    inc = _inc()
    inc.enrichment = Enrichment(confidence=0.9)
    inc.correlation = Correlation()
    inc.severity = Severity(score=50, needs_reenrichment=True)
    assert orchestrator.allowed_next(inc) == ["enrichment"]


def test_proposal_must_go_to_approval():
    inc = _inc()
    inc.enrichment = Enrichment(confidence=0.9)
    inc.correlation = Correlation()
    inc.severity = Severity(score=90)
    inc.proposals.append(Proposal(round=1, actions=[
        ProposedAction(action="block_ip", target="1.2.3.4")]))
    assert orchestrator.allowed_next(inc) == ["approval"]


def test_rejection_sends_back_to_playbook():
    inc = _inc()
    inc.enrichment = Enrichment(confidence=0.9)
    inc.correlation = Correlation()
    inc.severity = Severity(score=90)
    inc.proposals.append(Proposal(round=1, actions=[
        ProposedAction(action="isolate_host", target="h")]))
    inc.decisions.append(ApprovalDecision(round=1, decision="reject", reason="payroll"))
    assert orchestrator.allowed_next(inc) == ["playbook"]


def test_approval_ends_and_simulates_actions(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))
    inc = _inc()
    inc.enrichment = Enrichment(confidence=0.9)
    inc.correlation = Correlation()
    inc.severity = Severity(score=90)
    inc.proposals.append(Proposal(round=1, actions=[
        ProposedAction(action="block_ip", target="1.2.3.4")]))
    inc.decisions.append(ApprovalDecision(round=1, decision="approve", reason="ok"))
    inc = orchestrator.run(inc)
    assert inc.status == "contained"
    assert inc.executed_actions == ["block_ip 1.2.3.4 (SIMULATED)"]


def test_invalid_llm_choice_falls_back_to_allowed(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))
    monkeypatch.setattr(orchestrator.llm, "ask", _fake_llm("approval"))
    inc = _inc()
    inc.enrichment = Enrichment(known_benign=True, confidence=0.9)
    inc = orchestrator.run(inc)
    assert inc.next_agent in ("correlation", "end")


def test_llm_failure_falls_back_to_allowed(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))

    def boom(*a, **k):
        raise RuntimeError("down")

    monkeypatch.setattr(orchestrator.llm, "ask", boom)
    inc = _inc()
    inc.enrichment = Enrichment(known_benign=True, confidence=0.9)
    inc = orchestrator.run(inc)
    assert inc.next_agent == "correlation"


def test_error_status_escalates_to_human(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))
    inc = _inc()
    inc.status = "error"
    inc = orchestrator.run(inc)
    assert inc.next_agent == "human"
    assert inc.status == "error"