"""CMDB lookup tool (P3). Owned by P3; request changes via PR.

Backed by the static data/cmdb.json (6-8 synthetic assets: criticality,
owner, business function, maintenance window). In a real SOC this would
be a live CMDB API call; here it stands in as the project's synthetic
data source, per the task sheet.

The Approval agent is the main caller: it needs to know how critical an
asset is and whether now is inside its maintenance window before
deciding whether a proposed action (isolate_host, disable_user, etc.)
is worth the business disruption.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, TypedDict

CMDB_PATH = Path("data/cmdb.json")


class CMDBRecord(TypedDict):
    asset_id: str
    hostname: str
    criticality: str              # "low" | "medium" | "high" | "critical"
    owner: str
    business_function: str
    maintenance_window: str


def _load(path: Path = CMDB_PATH) -> list[CMDBRecord]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def lookup_host(hostname: str, path: Path = CMDB_PATH) -> Optional[CMDBRecord]:
    """Look up an asset by hostname (case-insensitive). Returns None for
    an unknown host rather than raising -- callers (Approval agent)
    should treat 'no CMDB record' as 'no extra business context
    available', not a crash."""
    if not hostname:
        return None
    hostname_lower = hostname.lower()
    for asset in _load(path):
        if asset["hostname"].lower() == hostname_lower:
            return asset
    return None


def lookup_asset_id(asset_id: str, path: Path = CMDB_PATH) -> Optional[CMDBRecord]:
    for asset in _load(path):
        if asset["asset_id"] == asset_id:
            return asset
    return None


def list_assets(path: Path = CMDB_PATH) -> list[CMDBRecord]:
    """All assets -- used by the Streamlit UI's reference panel and by tests."""
    return _load(path)
