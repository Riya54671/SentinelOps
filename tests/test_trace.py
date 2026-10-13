from lib.trace import log_event, read_trace


def test_log_and_read_back(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))
    log_event("INC-T", "orchestrator", "enrichment", "handoff", {"x": 1})
    log_event("INC-T", "enrichment", "orchestrator", "decision")

    events = read_trace("INC-T")
    assert len(events) == 2
    assert events[0].to_agent == "enrichment"
    assert events[0].payload == {"x": 1}
    assert events[1].event == "decision"


def test_read_missing_trace_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path))
    assert read_trace("DOES-NOT-EXIST") == []