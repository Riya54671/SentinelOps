"""LangGraph wiring. Owned by P1."""
from __future__ import annotations

import importlib
import uuid
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from agents import orchestrator
from lib import stubs
from lib.schemas import Alert, Incident
from lib.trace import log_event

WORKERS = ["enrichment", "correlation", "severity", "playbook", "approval"]


class GraphState(TypedDict):
    incident: Incident


def _load(name: str):
    """Use the real agent if its file defines run(); otherwise a stub."""
    try:
        mod = importlib.import_module(f"agents.{name}")
        if hasattr(mod, "run"):
            return mod.run
    except ImportError:
        pass
    return stubs.STUBS[name]


def _worker_node(name: str, fn):
    def node(state: GraphState) -> GraphState:
        inc = state["incident"]
        log_event(inc.incident_id, "orchestrator", name, "handoff", {"status": inc.status})
        try:
            inc = fn(inc)
        except Exception as e:  # one agent failing must not crash the run
            inc.status = "error"
            inc.log(name, f"FAILED: {e}")
            log_event(inc.incident_id, name, "orchestrator", "tool_error", {"error": str(e)})
        return {"incident": inc}
    return node


def _orchestrator_node(state: GraphState) -> GraphState:
    return {"incident": orchestrator.run(state["incident"])}


def _human_node(state: GraphState) -> GraphState:
    inc = state["incident"]
    if inc.status != "error":
        inc.status = "escalated_to_human"
    inc.log("human", "Escalated to a human analyst.")
    return {"incident": inc}


def build_graph():
    g = StateGraph(GraphState)
    g.add_node("orchestrator", _orchestrator_node)
    g.add_node("human", _human_node)
    for w in WORKERS:
        g.add_node(w, _worker_node(w, _load(w)))
        g.add_edge(w, "orchestrator")          # every worker reports back

    g.add_edge(START, "orchestrator")
    g.add_conditional_edges(
        "orchestrator",
        lambda s: s["incident"].next_agent,
        {**{w: w for w in WORKERS}, "human": "human", "end": END},
    )
    g.add_edge("human", END)
    return g.compile()


def run_incident(alert: Alert, incident_id: str | None = None) -> Incident:
    inc = Incident(incident_id=incident_id or f"INC-{uuid.uuid4().hex[:6]}",
                   alerts=[alert])
    try:
        out = build_graph().invoke({"incident": inc}, {"recursion_limit": 40})
        return out["incident"]
    except Exception as e:  # never crash the UI or the demo
        inc.status = "error"
        inc.log("orchestrator", f"Run aborted: {e}")
        log_event(inc.incident_id, "orchestrator", "human", "tool_error",
                  {"error": str(e)})
        return inc