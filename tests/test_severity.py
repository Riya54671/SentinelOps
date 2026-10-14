from agents import severity
from lib.schemas import Correlation, Enrichment


def _inc(make_incident, rep="malicious", conf=1.0, benign=False, related=3, attempts=0):
    inc = make_incident()
    inc.enrichment = Enrichment(ip_reputation=rep, confidence=conf, known_benign=benign)
    inc.correlation = Correlation(related_alert_ids=[f"A{i}" for i in range(related)])
    inc.enrichment_attempts = attempts
    return inc


def _llm(monkeypatch, score=None, reenrich=False):
    def fake(system, user, schema, **kw):
        if score is None:
            raise RuntimeError("no llm")
        return severity._Judgement(score=score, reasoning="test", needs_reenrichment=reenrich)
    monkeypatch.setattr(severity.llm, "ask", fake)


def test_fallback_score_is_high_for_malicious_with_related(make_incident, monkeypatch):
    _llm(monkeypatch)
    inc = severity.run(_inc(make_incident))
    assert inc.severity.score >= 70
    assert "rule-based" in inc.severity.reasoning


def test_known_benign_is_capped_low(make_incident, monkeypatch):
    _llm(monkeypatch, score=90)
    inc = severity.run(_inc(make_incident, rep="clean", benign=True, related=0))
    assert inc.severity.score <= 10


def test_llm_score_is_clamped_near_baseline(make_incident, monkeypatch):
    _llm(monkeypatch, score=100)
    inc = severity.run(_inc(make_incident, rep="clean", related=0))   # baseline 5
    assert inc.severity.score == 30   # 5 + 25


def test_can_request_reenrichment_on_weak_evidence(make_incident, monkeypatch):
    _llm(monkeypatch, score=40, reenrich=True)
    inc = severity.run(_inc(make_incident, rep="unknown", conf=0.3, related=0))
    assert inc.severity.needs_reenrichment is True


def test_no_reenrichment_after_attempts_exhausted(make_incident, monkeypatch):
    _llm(monkeypatch, score=40, reenrich=True)
    inc = severity.run(_inc(make_incident, rep="unknown", conf=0.3, related=0, attempts=2))
    assert inc.severity.needs_reenrichment is False