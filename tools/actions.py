"""Action catalog + simulated executor (P3). Owned by P3; request changes via PR.

The catalog is fixed to match lib.schemas.ActionType exactly
(isolate_host, block_ip, disable_user, reset_creds) -- the Playbook
agent may only propose these four, so the LLM can't invent an action
name that doesn't exist.

The executor is SIMULATED ONLY: it never calls a real firewall, IAM, or
EDR API. It logs "would have done X" as a string into
Incident.executed_actions and returns. That's a safety requirement for
this assignment, not a shortcut -- nothing here is allowed to touch
real infrastructure.
"""
from __future__ import annotations

from typing import Optional, TypedDict

from lib.schemas import ActionType, ProposedAction


class ActionDefinition(TypedDict):
    description: str
    target_hint: str              # what `target` should contain for this action


ACTION_CATALOG: dict[ActionType, ActionDefinition] = {
    "isolate_host": {
        "description": "Disconnect a host from the network (stays powered on) to stop lateral movement or exfiltration.",
        "target_hint": "hostname",
    },
    "block_ip": {
        "description": "Add a firewall rule blocking all traffic to/from an IP address.",
        "target_hint": "ip_address",
    },
    "disable_user": {
        "description": "Disable a user account in the identity provider, blocking further logins.",
        "target_hint": "username",
    },
    "reset_creds": {
        "description": "Force a password/credential reset for a user, invalidating existing sessions.",
        "target_hint": "username",
    },
}


def catalog_description() -> str:
    """Render the catalog for LLM prompts -- keeps prompts and the enum
    in sync instead of hardcoding action names in two places."""
    return "\n".join(
        f"- {action}: {defn['description']} (target = {defn['target_hint']})"
        for action, defn in ACTION_CATALOG.items()
    )


# Actions that take a host/account fully offline -- the disruptive end
# of the catalog. block_ip and reset_creds are surgical: they stop an
# attacker without interrupting the service, which is why the project's
# canonical scenario rejects an isolate_host proposal on a critical host
# and then approves block_ip + reset_creds for the same host.
DISRUPTIVE_ACTIONS = {"isolate_host", "disable_user"}


def is_high_impact(action: ProposedAction, cmdb_record: Optional[dict]) -> bool:
    """Rule-of-thumb the Approval agent's rule-based fallback leans on:
    a disruptive action (isolate_host, disable_user) on a high/critical
    asset deserves extra scrutiny before approval. A surgical action
    (block_ip, reset_creds) is never flagged here, even on a critical
    asset -- that's deliberate, see DISRUPTIVE_ACTIONS above."""
    if action.action not in DISRUPTIVE_ACTIONS:
        return False
    return bool(cmdb_record and cmdb_record.get("criticality") in ("high", "critical"))


def simulated_execute(action: ProposedAction) -> str:
    """Return the SIMULATED execution record for one action. This never
    calls a real API -- it's a formatted string that Incident.executed_actions
    stores, matching the shared sample_output.json convention
    (e.g. 'block_ip 185.220.101.45 (SIMULATED)')."""
    return f"{action.action} {action.target} (SIMULATED)"


def simulated_execute_all(actions: list[ProposedAction]) -> list[str]:
    return [simulated_execute(a) for a in actions]
