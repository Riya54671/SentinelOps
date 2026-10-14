"""Input validation (P3): malformed JSON / schema mismatch returns a
clear error rather than crashing. Mirrors the try/except in
app/streamlit_app.py's "Run pipeline" handler."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from lib.schemas import Alert


def test_malformed_json_raises_decode_error():
    bad = '{"alert_id": "A1", }'  # trailing comma
    with pytest.raises(json.JSONDecodeError):
        json.loads(bad)


def test_missing_required_field_raises_validation_error():
    payload = {"source": "firewall", "rule": "test"}  # missing alert_id, timestamp
    with pytest.raises(ValidationError):
        Alert(**payload)


def test_wrong_type_raises_validation_error():
    payload = {"alert_id": "A1", "timestamp": "2026-10-14T00:00:00Z",
               "source": "firewall", "rule": "test", "src_ip": 12345}  # should be str
    with pytest.raises(ValidationError):
        Alert(**payload)


def test_valid_minimal_alert_parses():
    payload = {"alert_id": "A1", "timestamp": "2026-10-14T00:00:00Z",
               "source": "firewall", "rule": "test"}
    alert = Alert(**payload)
    assert alert.alert_id == "A1"
    assert alert.src_ip is None
