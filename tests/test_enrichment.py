from agents import enrichment


def _intel(**kw):
    base = {"score": 95, "malicious": True, "tags": ["c2"], "confidence": 1.0,
            "sources_used": ["abuseipdb"], "sources_failed": [], "fallback_used": False}
    base.update(kw)
    return base


def _no_llm(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no llm")
    monkeypatch.setattr(enrichment.llm, "ask", boom)


def test_malicious_ip(make_incident, monkeypatch):
    _no_llm(monkeypatch)
    monkeypatch.setattr(enrichment.threat_intel, "lookup_ip", lambda ip: _intel())
    inc = enrichment.run(make_incident())
    assert inc.enrichment.ip_reputation == "malicious"
    assert inc.enrichment.known_benign is False


def test_known_benign_scanner(make_incident, monkeypatch):
    _no_llm(monkeypatch)
    monkeypatch.setattr(enrichment.threat_intel, "lookup_ip", lambda ip: _intel(
        score=0, malicious=False, tags=["internal", "approved-scanner"]))
    inc = enrichment.run(make_incident(src_ip="10.0.9.50"))
    assert inc.enrichment.known_benign is True
    assert inc.enrichment.ip_reputation == "clean"


def test_failed_sources_and_low_confidence_are_reported(make_incident, monkeypatch):
    _no_llm(monkeypatch)
    monkeypatch.setattr(enrichment.threat_intel, "lookup_ip", lambda ip: _intel(
        confidence=0.2, sources_used=["local_ioc"], fallback_used=True,
        sources_failed=["abuseipdb: ReadTimeout", "otx: HTTPError"]))
    inc = enrichment.run(make_incident())
    assert inc.enrichment.confidence == 0.2
    assert len(inc.enrichment.sources_failed) == 2


def test_no_source_ip_skips_lookup(make_incident, monkeypatch):
    _no_llm(monkeypatch)

    def should_not_run(ip):
        raise AssertionError("lookup called")
    monkeypatch.setattr(enrichment.threat_intel, "lookup_ip", should_not_run)
    inc = enrichment.run(make_incident(src_ip=None))
    assert inc.enrichment.ip_reputation == "unknown"


def test_tool_crash_sets_error_status(make_incident, monkeypatch):
    _no_llm(monkeypatch)

    def crash(ip):
        raise ValueError("boom")
    monkeypatch.setattr(enrichment.threat_intel, "lookup_ip", crash)
    inc = enrichment.run(make_incident())
    assert inc.status == "error"