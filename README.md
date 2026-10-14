# SentinelOps: Multi-Agent SOC Alert Triage

SentinelOps is a simulated Security Operations Center (SOC) that cuts through alert overload. Five coordinating agents investigate each alert, assess its risk, propose a containment response, and have that response checked against **business impact** before anything is (simulated) executed. All agents work on one shared incident record, so every decision is traceable.

> **Safety:** SentinelOps never touches real infrastructure. Response actions are logged as strings tagged `(SIMULATED)`.

## What it does

| # | Agent | Job |
|---|-------|-----|
| 1 | **Enrichment** | Adds threat-intelligence context (IP reputation from AbuseIPDB, VirusTotal, OTX) |
| 2 | **Correlation** | Links related alerts (same host, user, IP, time window) into one incident |
| 3 | **Severity** | Scores the incident 0–100; may request one bounded re-enrichment |
| 4 | **Playbook** | Proposes 1–2 containment actions from a fixed catalog; revises using rejection feedback |
| 5 | **Business-Impact Approval** | Weighs the proposal against asset criticality and maintenance windows, then **approves, modifies, or rejects** |

A **LangGraph orchestrator** is the only component that decides which agent runs next. Agents never call each other.

## Methodology

![Methodology](docs/methodology.png)

1. **Ingest.** One alert (JSON) is validated into an `Alert` and wrapped in a shared `Incident`.
2. **Enrich → Correlate → Score.** Each agent writes only its own field on the incident. If evidence is insufficient, Severity can send the incident back for **one** re-enrichment.
3. **Propose.** Playbook picks one or two actions from the fixed action catalog.
4. **Review.** Approval looks up the asset in the (synthetic) CMDB. An LLM judges the proposal, then a **deterministic policy check** (`_enforce_policy`) overrides it where a hard rule applies: *a critical asset is never isolated outside its maintenance window.*
   - **approve** → actions go to simulated execution
   - **modify** → only the safe subset executes; the rest is deferred
   - **reject** → back to Playbook with reason and constraints (max `MAX_REVISION_ROUNDS = 3`, then **escalate to a human**)
5. **Execute (simulated) and audit.** Actions are logged, the final incident is shown in Streamlit, and every hand-off and decision is appended to `traces/{incident_id}.jsonl`.

Safeguards: `MAX_STEPS = 20` bounds every run. If an LLM call fails, agents fall back from Gemini to Groq to deterministic rules. An agent failure marks the incident as errored instead of crashing the run.

## Input definition

The pipeline takes **one alert per run** as JSON.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alert_id` | string | yes | Unique alert ID, e.g. `A001` |
| `timestamp` | string (ISO-8601, UTC) | yes | When the alert fired, e.g. `2026-10-12T02:10:00Z`. Also used for the maintenance-window check |
| `source` | string | yes | Detection source, e.g. `EDR` |
| `rule` | string | yes | Detection rule name |
| `src_ip` | string (IPv4) | yes | Source IP; the indicator that gets enriched |
| `dest_ip` | string (IPv4) | no | Destination IP |
| `host` | string | yes | Affected hostname; stored as `dest_host`; used for the CMDB lookup |
| `user` | string | no | Account involved |
| `description` | string | yes | Raw log text; stored as `raw_log` |
| `raw_severity` | string | no | Source-assigned severity, e.g. `high` |
| `scenario` | string | no | Demo label, e.g. `S1_rejection_loop` |

Example:

```json
{
  "alert_id": "A001",
  "scenario": "S1_rejection_loop",
  "timestamp": "2026-10-12T02:10:00Z",
  "source": "EDR",
  "rule": "Suspicious PowerShell Download Cradle",
  "host": "fin-db-01",
  "user": "svc_backup",
  "src_ip": "185.220.101.45",
  "dest_ip": "10.0.5.20",
  "description": "PowerShell spawned by winword.exe downloading remote payload",
  "raw_severity": "high"
}
```

**Reference data used during a run** (not supplied by the user):
- **CMDB** (`data/cmdb.json`): synthetic asset records with `hostname`, `criticality`, `owner`, `business_function`, `maintenance_window` (e.g. `Sun 02:00-04:00 IST`). A host with no record is treated as missing context, not an error.
- **Alert store**: earlier alerts (e.g. `A002`–`A007`) used for correlation.
- **Action catalog** (`tools/actions.py`): the fixed set of response actions, e.g. `isolate_host`, `disable_user`, `block_ip`, `reset_creds`.

## Output definition

The output is the final **`Incident`** object (Pydantic model in `lib/schemas.py`), shown in the Streamlit UI and written to the trace.

| Field | Description |
|-------|-------------|
| `incident_id` | e.g. `INC-84fc56ea` |
| `alerts` | The submitted alert(s) |
| `enrichment` | `ip_reputation`, `confidence`, `known_benign`, `indicators`, `sources_used`, `sources_failed`, `notes` |
| `correlation` | `related_alert_ids`, `merged_into_existing`, `reasoning` |
| `severity` | `score` (0–100), `reasoning`, `needs_reenrichment` |
| `proposals` | One entry per Playbook round: `round`, `actions` (`action`, `target`, `params`), `rationale` |
| `decisions` | One entry per Approval round: `round`, `decision` (`approve` / `modify` / `reject`), `reason`, `constraints`, `modified_actions` |
| `executed_actions` | Simulated execution log, e.g. `block_ip 185.220.101.45 (SIMULATED)` |
| `status` | Final state, e.g. `contained`; escalation and error states are also possible |
| `revision_round` | Number of rejection rounds used |
| `audit_trail` | Timestamped messages from every agent and orchestrator hand-off |

**Trace file:** `traces/{incident_id}.jsonl` is an append-only record of hand-offs, proposals, decisions, and execution, one JSON event per line.

**Example result** (alert `A001` above):

| | |
|---|---|
| Severity | 85/100 |
| Playbook proposal | `isolate_host` → `fin-db-01`, `block_ip` → `185.220.101.45` |
| Approval | **modify**: `fin-db-01` is critical (payroll and general ledger database); isolation is blocked outside its maintenance window, so only the IP block proceeds |
| Executed | `block_ip 185.220.101.45 (SIMULATED)` |
| Status | `contained` |

## Setup

```bash
git clone https://github.com/Riya54671/SentinelOps.git
cd SentinelOps
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then add your API keys
```

`.env` holds the LLM keys (Gemini, Groq) and threat-intelligence keys (AbuseIPDB, VirusTotal, OTX). Never commit `.env`.

## Run

```bash
streamlit run app/streamlit_app.py
```

If you change agent code, restart Streamlit. A browser refresh does not reload imported modules.

## Run tests

```bash
pytest
```

## Demo scenarios

| Scenario | What it shows |
|----------|---------------|
| `S1_rejection_loop` | Critical finance host; Approval blocks isolation outside the maintenance window; the Playbook/Approval review loop |

## Project structure

```
agents/      enrichment, correlation, severity, playbook, approval, orchestrator
lib/         schemas (Pydantic), llm (Gemini → Groq), trace writer
tools/       cmdb lookup, action catalog, simulated executor
app/         Streamlit interface
traces/      generated JSONL audit traces (git-ignored)
docs/        diagrams
```

## Known limitations

- Response execution is simulated by design.
- The CMDB and alert store are synthetic datasets.
- Threat intelligence covers IP reputation only.

## Team

Symbiosis Institute of Technology, Pune

- Reuel Menon (23070122178)
- Riya Agrawal (23070122184)
- Saumya Kumar (23070122195)