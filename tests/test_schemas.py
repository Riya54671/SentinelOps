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

def test_alert_accepts_seed_data_format():
    a = Alert.model_validate({
        "alert_id": "A001", "scenario": "S1_rejection_loop",
        "timestamp": "2026-10-12T02:10:00Z", "source": "EDR",
        "rule": "Suspicious PowerShell Download Cradle",
        "host": "fin-db-01", "user": "svc_backup",
        "src_ip": "185.220.101.45", "dest_ip": "10.0.5.20",
        "description": "PowerShell spawned by winword.exe downloading remote payload",
        "raw_severity": "high"})
    assert a.dest_host == "fin-db-01"
    assert a.raw_log.startswith("PowerShell")