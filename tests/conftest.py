import pytest

from lib.schemas import Alert, Incident


@pytest.fixture(autouse=True)
def _trace_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_DIR", str(tmp_path / "traces"))


@pytest.fixture
def make_incident():
    def _make(**alert_overrides):
        data = dict(alert_id="T-1", timestamp="2026-10-12T02:30:00Z", source="firewall",
                    rule="Multiple failed SSH logins", src_ip="185.220.101.45",
                    dest_host="fin-db-01", user="svc_backup", raw_log="failed password")
        data.update(alert_overrides)
        return Incident(incident_id="INC-T", alerts=[Alert(**data)])
    return _make