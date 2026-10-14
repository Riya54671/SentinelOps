import json
import os
import sqlite3
import time
import ipaddress
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

CACHE_DB = Path("data/intel_cache.db")
IOC_FILE = Path("data/ioc.json")
CACHE_TTL_SECONDS = 24 * 3600
TIMEOUT = 15   # seconds per API call


# ---------- cache ----------
def _conn(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS intel_cache ("
        "provider TEXT, ip TEXT, response TEXT, fetched_at REAL, "
        "PRIMARY KEY (provider, ip))"
    )
    return conn


def cache_get(provider, ip, db_path=CACHE_DB, ttl=CACHE_TTL_SECONDS):
    with _conn(db_path) as conn:
        row = conn.execute(
            "SELECT response, fetched_at FROM intel_cache WHERE provider=? AND ip=?",
            (provider, ip)).fetchone()
    if row and (time.time() - row[1]) < ttl:
        return json.loads(row[0])
    return None


def cache_set(provider, ip, result, db_path=CACHE_DB):
    with _conn(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO intel_cache VALUES (?,?,?,?)",
            (provider, ip, json.dumps(result), time.time()))


# ---------- individual providers ----------
def _normalize(provider, ip, score, tags):
    score = max(0, min(100, int(score)))
    return {"provider": provider, "ip": ip, "score": score,
            "malicious": score >= 50, "tags": tags}


def query_abuseipdb(ip):
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        raise RuntimeError("ABUSEIPDB_API_KEY missing")
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=TIMEOUT)
    r.raise_for_status()
    d = r.json()["data"]
    tags = []
    if d.get("totalReports"):
        tags.append(f"{d['totalReports']}-reports")
    if d.get("usageType"):
        tags.append(d["usageType"])
    return _normalize("abuseipdb", ip, d.get("abuseConfidenceScore", 0), tags)


def query_virustotal(ip):
    key = os.getenv("VT_API_KEY")
    if not key:
        raise RuntimeError("VT_API_KEY missing")
    r = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": key}, timeout=TIMEOUT)
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    tags = [f"vt-malicious-{mal}", f"vt-suspicious-{sus}"]
    return _normalize("virustotal", ip, mal * 12 + sus * 5, tags)


def query_otx(ip):
    key = os.getenv("OTX_API_KEY")
    if not key:
        raise RuntimeError("OTX_API_KEY missing")
    r = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers={"X-OTX-API-KEY": key}, timeout=TIMEOUT)
    r.raise_for_status()
    pulses = r.json().get("pulse_info", {}).get("count", 0)
    return _normalize("otx", ip, pulses * 10, [f"otx-pulses-{pulses}"])


PROVIDERS = {
    "abuseipdb": query_abuseipdb,
    "virustotal": query_virustotal,
    "otx": query_otx,
}


# ---------- fallback ----------
def ioc_lookup(ip, ioc_path=IOC_FILE):
    with open(ioc_path, encoding="utf-8") as f:
        data = json.load(f)
    entry = data["ips"].get(ip) or data["default"]
    return {"provider": entry.get("source", "local_ioc"), "ip": ip,
            "score": entry["score"], "malicious": entry["malicious"],
            "tags": entry["tags"]}


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # treat malformed IPs as non-queryable


# ---------- main entry point ----------
def lookup_ip(ip, db_path=CACHE_DB, ioc_path=IOC_FILE, providers=None):
    """Returns a combined intel result. Never raises.

    Keys: ip, score (0-100), malicious (bool), tags, sources_used,
          sources_failed, fallback_used (bool), confidence (0-1)
    """
    providers = providers or PROVIDERS
    result = {"ip": ip, "sources_used": [], "sources_failed": [],
              "fallback_used": False}

    if _is_private(ip):
        ioc = ioc_lookup(ip, ioc_path)
        result.update(score=ioc["score"], malicious=ioc["malicious"],
                      tags=ioc["tags"] + ["private-or-invalid-ip"],
                      sources_used=["local_ioc"], fallback_used=True,
                      confidence=0.5)
        return result

    findings = []
    force_fail = os.getenv("FORCE_INTEL_FAILURE") == "1"  # for the demo

    for name, fn in providers.items():
        cached = cache_get(name, ip, db_path)
        if cached:
            findings.append(cached)
            result["sources_used"].append(f"{name}(cache)")
            continue
        try:
            if force_fail:
                raise RuntimeError("simulated API failure")
            data = fn(ip)
            cache_set(name, ip, data, db_path)
            findings.append(data)
            result["sources_used"].append(name)
        except Exception as e:  # timeout, 429, missing key, bad JSON...
            result["sources_failed"].append(f"{name}: {type(e).__name__}")

    if findings:
        scores = [f["score"] for f in findings]
        avg = sum(scores) / len(scores)
        tags = sorted({t for f in findings for t in f["tags"]})
        result.update(score=int(avg), malicious=avg >= 50, tags=tags,
                      confidence=round(len(findings) / len(providers), 2))
        return result

    # every live source failed -> offline IOC fallback
    ioc = ioc_lookup(ip, ioc_path)
    known = ioc["provider"] == "local_ioc"
    result.update(score=ioc["score"], malicious=ioc["malicious"],
                  tags=ioc["tags"], sources_used=["local_ioc"],
                  fallback_used=True, confidence=0.4 if known else 0.2)
    return result


if __name__ == "__main__":
    for test_ip in ["185.220.101.45", "10.0.9.50", "8.8.8.8"]:
        print(json.dumps(lookup_ip(test_ip), indent=2))
