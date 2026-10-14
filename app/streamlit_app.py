"""SentinelOps Streamlit frontend (P3).

Paste or upload one alert, run the full LangGraph pipeline (P1's
orchestrator decides routing: enrichment -> correlation -> severity ->
playbook <-> approval, up to 3 rejection rounds, then human escalation),
and show a live agent-by-agent feed plus the final incident view.

Run from the repo root:
    streamlit run app/streamlit_app.py
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents import approval, correlation, enrichment, orchestrator, playbook, severity  # noqa: E402
from lib.schemas import Alert, Incident  # noqa: E402
from lib.trace import read_trace  # noqa: E402
from tools import cmdb  # noqa: E402

AGENT_FNS = {
    "enrichment": enrichment.run,
    "correlation": correlation.run,
    "severity": severity.run,
    "playbook": playbook.run,
    "approval": approval.run,
}

SAMPLE_ALERT = {
    "alert_id": f"UI-{uuid.uuid4().hex[:6]}",
    "timestamp": "2026-10-14T10:00:00Z",
    "source": "AD",
    "rule": "Service Account Interactive Logon",
    "src_ip": "185.220.101.45",
    "dest_host": "fin-db-01",
    "user": "svc_backup",
    "raw_log": "svc_backup logged on interactively from external IP",
}

MAX_STEPS = 20  # safety cap so a routing bug can't spin forever in the UI


def run_pipeline(inc: Incident) -> Incident:
    for _ in range(MAX_STEPS):
        inc = orchestrator.run(inc)
        if inc.next_agent in ("end", "human", None):
            break
        fn = AGENT_FNS.get(inc.next_agent)
        if fn is None:
            break
        inc = fn(inc)
        if inc.status == "error":
            break
    return inc


def render_trace(incident_id: str) -> None:
    for ev in read_trace(incident_id):
        with st.chat_message("assistant"):
            st.markdown(f"**{ev.from_agent} -> {ev.to_agent}** ({ev.event})")
            if ev.payload:
                with st.expander("details"):
                    st.json(ev.payload)


def render_final(inc: Incident) -> None:
    st.subheader("Final incident state")
    c1, c2, c3 = st.columns(3)
    c1.metric("Status", inc.status)
    c2.metric("Severity", f"{inc.severity.score}/100" if inc.severity else "n/a")
    c3.metric("Revision rounds", inc.revision_round)

    host = inc.alerts[0].dest_host if inc.alerts else None
    record = cmdb.lookup_host(host) if host else None
    if record:
        st.markdown("**Asset context (CMDB)**")
        st.json(record)

    if inc.proposals:
        st.markdown("**Playbook proposal history**")
        for p in inc.proposals:
            st.write(f"Round {p.round}: " + ", ".join(f"{a.action} -> {a.target}" for a in p.actions))

    if inc.decisions:
        st.markdown("**Approval decision history**")
        for d in inc.decisions:
            st.write(f"Round {d.round}: {d.decision} — {d.reason}")

    if inc.executed_actions:
        st.markdown("**Simulated execution log** (nothing here touched real infrastructure)")
        st.json(inc.executed_actions)

    st.markdown("**Full incident JSON**")
    st.json(json.loads(inc.model_dump_json()))


def main() -> None:
    st.set_page_config(page_title="SentinelOps", layout="wide")
    st.title("SentinelOps — Multi-Agent SOC Simulation")
    st.caption("Paste or upload one SIEM-style alert. The system enriches, correlates, scores, "
               "proposes a response, and runs a business-impact approval loop before simulated execution.")

    with st.expander("Known CMDB assets (for reference)"):
        st.json(cmdb.list_assets())

    tab1, tab2 = st.tabs(["Paste JSON", "Upload file"])
    alert_text = None
    with tab1:
        alert_text = st.text_area("Alert JSON", value=json.dumps(SAMPLE_ALERT, indent=2), height=260)
    with tab2:
        uploaded = st.file_uploader("Upload alert .json", type=["json"])
        if uploaded is not None:
            alert_text = uploaded.read().decode("utf-8")

    if st.button("Run pipeline", type="primary"):
        try:
            parsed = json.loads(alert_text)
            alert = Alert(**parsed)
        except json.JSONDecodeError as e:
            st.error(f"That isn't valid JSON: {e}")
            return
        except Exception as e:
            st.error(f"Alert JSON didn't match the expected schema: {e}")
            return

        inc = Incident(incident_id=f"INC-{uuid.uuid4().hex[:8]}", alerts=[alert])
        with st.spinner("Running agent pipeline..."):
            inc = run_pipeline(inc)

        st.success(f"Pipeline finished for {inc.incident_id} — status: {inc.status}")
        st.markdown("### Live agent-by-agent feed")
        render_trace(inc.incident_id)
        render_final(inc)


if __name__ == "__main__":
    main()
