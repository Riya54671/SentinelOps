"""Unit tests for the Response Playbook Agent (P3). Never calls a real
LLM -- monkeypatches lib.llm.ask so the suite runs offline in CI."""
from __future__ import annotations

from agents import playbook
from lib.schemas import ApprovalDecision, ProposedAction


def test_round_1_has_no_feedback(make_incident, monkeypatch):
    def fake_ask(system, user, schema, **kw):
        return schema(actions=[ProposedAction(action="isolate_host", target="fin-db-01")],
                      rationale="contain the host")
    monkeypatch.setattr(playbook.llm, "ask", fake_ask)

    inc = make_incident()
    inc.severity = __import__("lib.schemas", fromlist=["Severity"]).Severity(score=80, reasoning="x")
    result = playbook.run(inc)

    assert len(result.proposals) == 1
    assert result.proposals[0].round == 1
    assert result.proposals[0].actions[0].action == "isolate_host"


def test_revision_round_picks_up_rejection_feedback(make_incident, monkeypatch):
    def fake_ask(system, user, schema, **kw):
        assert "do not isolate" in user
        return schema(actions=[ProposedAction(action="block_ip", target="185.220.101.45")],
                      rationale="revised per feedback")
    monkeypatch.setattr(playbook.llm, "ask", fake_ask)

    inc = make_incident()
    inc.proposals.append(__import__("lib.schemas", fromlist=["Proposal"]).Proposal(
        round=1, actions=[ProposedAction(action="isolate_host", target="fin-db-01")], rationale="r"))
    inc.decisions.append(ApprovalDecision(round=1, decision="reject",
                                           reason="do not isolate the host, it's critical",
                                           constraints=["prefer block_ip"]))

    result = playbook.run(inc)
    assert result.proposals[-1].round == 2
    assert result.proposals[-1].actions[0].action == "block_ip"


def test_falls_back_to_rule_based_on_llm_error(make_incident, monkeypatch):
    def raise_error(*a, **kw):
        raise RuntimeError("simulated outage")
    monkeypatch.setattr(playbook.llm, "ask", raise_error)

    inc = make_incident(user="svc_backup")
    inc.severity = __import__("lib.schemas", fromlist=["Severity"]).Severity(score=80, reasoning="x")
    result = playbook.run(inc)

    # fallback rule: user present + high severity -> disable_user
    assert result.proposals[0].actions[0].action == "disable_user"
    assert result.proposals[0].actions[0].target == "svc_backup"
    assert result.status != "error"


def test_does_not_crash_on_malformed_llm_output(make_incident, monkeypatch):
    def raise_validation(*a, **kw):
        raise ValueError("bad shape")
    monkeypatch.setattr(playbook.llm, "ask", raise_validation)

    inc = make_incident(dest_host="web-app-02")
    result = playbook.run(inc)

    assert result.status != "error"
    assert len(result.proposals) == 1
