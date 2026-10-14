import json
from tools import threat_intel as ti


def _ioc(tmp_path):
    p = tmp_path / "ioc.json"
    p.write_text(json.dumps({
        "ips": {"1.2.3.4": {"malicious": True, "score": 90, "tags": ["c2"],
                            "source": "local_ioc"}},
        "default": {"malicious": False, "score": 10, "tags": ["unknown"],
                    "source": "local_ioc_default"}}))
    return p


def _fail(ip):
    raise TimeoutError("boom")


def _ok(ip):
    return {"provider": "fake", "ip": ip, "score": 80, "malicious": True,
            "tags": ["fake-tag"]}


def test_all_providers_fail_uses_ioc(tmp_path):
    r = ti.lookup_ip("1.2.3.4", db_path=tmp_path / "c.db",
                     ioc_path=_ioc(tmp_path), providers={"a": _fail, "b": _fail})
    assert r["fallback_used"] is True
    assert r["malicious"] is True
    assert len(r["sources_failed"]) == 2


def test_unknown_ip_uses_default(tmp_path):
    r = ti.lookup_ip("9.9.9.9", db_path=tmp_path / "c.db",
                     ioc_path=_ioc(tmp_path), providers={"a": _fail})
    assert r["fallback_used"] is True
    assert r["confidence"] == 0.2


def test_partial_failure_lowers_confidence(tmp_path):
    r = ti.lookup_ip("1.2.3.4", db_path=tmp_path / "c.db",
                     ioc_path=_ioc(tmp_path), providers={"a": _ok, "b": _fail})
    assert r["fallback_used"] is False
    assert r["confidence"] == 0.5


def test_cache_prevents_second_call(tmp_path):
    calls = {"n": 0}

    def counting(ip):
        calls["n"] += 1
        return _ok(ip)

    db = tmp_path / "c.db"
    ti.lookup_ip("1.2.3.4", db_path=db, ioc_path=_ioc(tmp_path),
                 providers={"a": counting})
    ti.lookup_ip("1.2.3.4", db_path=db, ioc_path=_ioc(tmp_path),
                 providers={"a": counting})
    assert calls["n"] == 1


def test_private_ip_skips_apis(tmp_path):
    r = ti.lookup_ip("10.0.9.50", db_path=tmp_path / "c.db",
                     ioc_path=_ioc(tmp_path), providers={"a": _fail})
    assert r["sources_failed"] == []
    assert r["fallback_used"] is True