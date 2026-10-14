from tools import alert_store as store


def _db(tmp_path):
    db = tmp_path / "t.db"
    store.load_seed_alerts(db_path=db)
    return db


def test_query_by_host(tmp_path):
    rows = store.query_by_host("fin-db-01", db_path=_db(tmp_path))
    assert len(rows) == 6


def test_query_by_ip(tmp_path):
    rows = store.query_by_ip("185.220.101.45", db_path=_db(tmp_path))
    assert {r["alert_id"] for r in rows} >= {"A001", "A002", "A003"}


def test_query_by_user(tmp_path):
    rows = store.query_by_user("priya.m", db_path=_db(tmp_path))
    assert len(rows) >= 6


def test_time_window(tmp_path):
    rows = store.query_by_time_window(
        "2026-10-12T09:00:00Z", "2026-10-12T09:15:00Z", db_path=_db(tmp_path))
    assert all(r["scenario"] == "S2_false_positive" for r in rows)


def test_query_related_excludes_self(tmp_path):
    db = _db(tmp_path)
    alert = store.query_by_host("fin-db-01", db_path=db)[0]
    related = store.query_related(alert, db_path=db)
    assert alert["alert_id"] not in {r["alert_id"] for r in related}
    assert len(related) > 0