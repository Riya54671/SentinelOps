"""Run one alert through the SentinelOps graph from the command line."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pydantic import ValidationError

from lib.graph import run_incident
from lib.schemas import Alert

if len(sys.argv) != 2:
    sys.exit("Usage: python run_scenario.py <alert.json>")

try:
    alert = Alert.model_validate_json(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (ValidationError, ValueError, OSError) as e:
    sys.exit(f"Invalid alert input: {e}")

inc = run_incident(alert)

print(f"\nIncident {inc.incident_id}: status = {inc.status}\n")
for e in inc.audit_trail:
    print(f"[{e.agent}] {e.message}")
print(f"\nExecuted (simulated): {inc.executed_actions}")
print(f"Trace file: traces/{inc.incident_id}.jsonl")