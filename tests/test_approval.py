"""Unit tests for the Business-Impact Approval Agent (P3)."""
from __future__ import annotations

from agents import approval
from lib.schemas import Proposal, ProposedAction


def _with_proposal(make_incident, dest_host, action="isolate_host"):
    inc = make_incident(dest_host=dest_host)
    inc.proposals.append(Proposal(round=1, actions=[ProposedAction(action=action, target=dest_host)],
                                   rationale="r"))
    return inc


def test_approves_via_llm(make_incident, monkeypatch):
    def fake_ask(system, user, schema, **kw):
        return schema(decision="approve", reason="low risk", constraints=[])
    monkeypatch.setattr(approval.llm, "ask", fake_ask)

    inc = _with_proposal(make_incident, "dev-sandbox-01")
    result = approval.run(inc)

    assert result.decisions[-1].decision == "approve"
    assert result.decisions[-1].round == 1


def test_rejects_critical_asset_on_llm_error(make_incident, monkeypatch):
    def raise_error(*a, **kw):
        raise RuntimeError("simulated outage")
    monkeypatch.setattr(approval.llm, "ask", raise_error)

    inc = _with_proposal(make_incident, "fin-db-01", action="isolate_host")
    result = approval.run(inc)

    assert result.decisions[-1].decision == "reject"
    assert "CRITICAL" in result.decisions[-1].reason
    assert result.status != "error"


def test_modifies_high_impact_action_on_non_critical_asset(make_incident, monkeypatch):
    def raise_error(*a, **kw):
        raise RuntimeError("simulated outage")
    monkeypatch.setattr(approval.llm, "ask", raise_error)

    inc = _with_proposal(make_incident, "jump-01", action="disable_user")
    result = approval.run(inc)

    assert result.decisions[-1].decision == "modify"
    assert result.decisions[-1].constraints


def test_does_not_crash_with_no_cmdb_record(make_incident, monkeypatch):
    def raise_error(*a, **kw):
        raise RuntimeError("simulated outage")
    monkeypatch.setattr(approval.llm, "ask", raise_error)

    inc = _with_proposal(make_incident, "totally-unknown-host", action="isolate_host")
    result = approval.run(inc)

    assert result.status != "error"
    assert result.decisions[-1].decision == "approve"  # no CMDB record -> not flagged high-impact
