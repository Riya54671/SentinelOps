from pathlib import Path

from lib.schemas import Alert, Incident

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def test_sample_input_is_valid_alert():
    alert = Alert.model_validate_json((SAMPLES / "sample_input.json").read_text())
    assert alert.alert_id == "A-1042"
    assert alert.dest_host == "payroll-srv-01"


def test_sample_output_is_valid_incident():
    inc = Incident.model_validate_json((SAMPLES / "sample_output.json").read_text())
    assert inc.status == "contained"
    assert len(inc.proposals) == 2
    assert [d.decision for d in inc.decisions] == ["reject", "approve"]
    assert inc.revision_round == 1


def test_sample_output_input_alert_is_included():
    alert = Alert.model_validate_json((SAMPLES / "sample_input.json").read_text())
    inc = Incident.model_validate_json((SAMPLES / "sample_output.json").read_text())
    assert alert.alert_id in [a.alert_id for a in inc.alerts]