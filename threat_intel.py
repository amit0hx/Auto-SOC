"""
threat_intel.py — IP reputation / threat-intelligence lookup for Auto-SOC

Given an attacker IP, returns a reputation verdict. Uses the free AbuseIPDB API
when an ABUSEIPDB_KEY is configured (in .env); otherwise degrades to an offline
heuristic (internal vs external) so the dashboard always works.

Only public IPs are queried; private/LAN/loopback addresses are reported locally.
Results are cached per IP for the session.
"""

import ipaddress
import json
import os
import urllib.parse
import urllib.request

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

_cache = {}


def _is_public(ip):
    try:
        o = ipaddress.ip_address(ip)
        return not (o.is_private or o.is_link_local or o.is_loopback or o.is_multicast)
    except ValueError:
        return False


def check_ip(ip, timeout=4):
    """Return {score, label, source, detail} for an IP (cached)."""
    if ip in _cache:
        return _cache[ip]

    if not _is_public(ip):
        res = {"score": None, "label": "internal", "source": "offline",
               "detail": "private / LAN address"}
        _cache[ip] = res
        return res

    key = os.getenv("ABUSEIPDB_KEY")
    if not key:
        res = {"score": None, "label": "external", "source": "offline",
               "detail": "no ABUSEIPDB_KEY — set it in .env for live reputation"}
        _cache[ip] = res
        return res

    try:
        url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
            {"ipAddress": ip, "maxAgeInDays": 90})
        req = urllib.request.Request(
            url, headers={"Key": key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)["data"]
        score = int(data.get("abuseConfidenceScore", 0))
        label = "malicious" if score >= 50 else ("suspicious" if score >= 10 else "clean")
        res = {
            "score": score, "label": label, "source": "AbuseIPDB",
            "detail": f"{data.get('totalReports', 0)} reports · "
                      f"{data.get('countryCode', '?')} · {data.get('isp', '?')}",
        }
    except Exception as e:
        res = {"score": None, "label": "lookup-failed", "source": "offline",
               "detail": str(e)[:50]}
    _cache[ip] = res
    return res


def badge(res):
    """Short human-readable label for tables, e.g. 'malicious (87)' or 'external'."""
    if res.get("score") is not None:
        return f"{res['label']} ({res['score']})"
    return res["label"]
