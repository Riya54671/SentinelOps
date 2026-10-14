from agents import correlation
from tools import alert_store


def _setup(monkeypatch, tmp_path, llm_fn=None):
    monkeypatch.setattr(correlation, "DB_PATH", tmp_path / "t.db")

    def boom(*a, **k):
        raise RuntimeError("no llm")
    monkeypatch.setattr(correlation.llm, "ask", llm_fn or boom)


def test_merges_when_related_alerts_exist(make_incident, monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    inc = correlation.run(make_incident())
    assert inc.correlation.merged_into_existing is True
    assert len(inc.correlation.related_alert_ids) > 0


def test_new_incident_when_nothing_related(make_incident, monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    inc = correlation.run(make_incident(
        alert_id="T-2", dest_host="lonely-host", user="nobody", src_ip="9.9.9.9"))
    assert inc.correlation.merged_into_existing is False
    assert inc.correlation.related_alert_ids == []


def test_llm_ids_outside_candidates_are_dropped(make_incident, monkeypatch, tmp_path):
    def fake(system, user, schema, **kw):
        return correlation._Judgement(related_alert_ids=["A001", "FAKE-99"], reasoning="x")
    _setup(monkeypatch, tmp_path, fake)
    inc = correlation.run(make_incident())
    assert inc.correlation.related_alert_ids == ["A001"]


def test_alert_is_stored_for_future_correlation(make_incident, monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    correlation.run(make_incident(alert_id="T-3", dest_host="lonely-host",
                                  user="nobody", src_ip="9.9.9.9"))
    rows = alert_store.query_by_host("lonely-host", db_path=tmp_path / "t.db")
    assert [r["alert_id"] for r in rows] == ["T-3"]