#!/usr/bin/env python3
"""
gapi_probe — Google API Key Tester
Tests a Google API key against 50+ endpoints across 15+ services.
Real-time colored output, CVSS estimation, cost impact calculator.

Usage:
    python3 gapi_probe.py AIzaSy...
    python3 gapi_probe.py AIzaSy... --json report.json
"""

import sys
import time
import json
import re
import threading
import argparse
import itertools
from urllib.parse import urlencode
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
except ImportError:
    print("[-] Install requests: pip3 install requests")
    sys.exit(1)

# ── ANSI Colors ──────────────────────────────────────────────────────────────
C = {
    "R": "\033[91m", "G": "\033[92m", "Y": "\033[93m", "B": "\033[94m",
    "M": "\033[95m", "C": "\033[96m", "W": "\033[97m", "D": "\033[90m",
    "BR": "\033[1;91m", "BG": "\033[1;92m", "BY": "\033[1;93m",
    "BC": "\033[1;96m", "BW": "\033[1;97m",
    "N": "\033[0m",
}
SPINNER = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
SUMMARY = []
PROJECT_ID = None  # discovered from error messages during probing
PROJECT_RE = re.compile(r"project (\d+)")  # extracts project number from errors


# ── Progress Spinner ────────────────────────────────────────────────────────
class Progress:
    def __init__(self, msg):
        self.msg = msg
        self.done = False
        self._t = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        while not self.done:
            sys.stderr.write(f"\r{C['BC']}[{next(SPINNER)}]{C['N']} {self.msg}   ")
            sys.stderr.flush()
            time.sleep(0.1)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *a):
        self.done = True
        self._t.join(timeout=0.3)
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.flush()


# ── Endpoint Definitions ────────────────────────────────────────────────────
@dataclass
class Endpoint:
    name: str
    method: str = "GET"
    url: str = ""
    body: Optional[dict] = None
    headers: dict = field(default_factory=dict)
    billable: bool = False
    cost_per_call: float = 0.0
    cost_unit: str = "call"
    monthly_volume_desc: str = ""
    valid_status: list = field(default_factory=lambda: [200])
    invalid_status: list = field(default_factory=lambda: [400, 403])
    response_field: str = ""       # JSON field to check for validity
    response_value: str = ""       # Expected value in that field
    cvss_if_valid: str = ""
    impact_desc: str = ""

SERVICES = {
    "🗺️ Maps (billable)": [
        Endpoint(
            "Geocoding",
            url="https://maps.googleapis.com/maps/api/geocode/json?address=Googleplex&key=***",
            billable=True, cost_per_call=0.005, cost_unit="request",
            monthly_volume_desc="1M req/month → ~$5,000/month",
            valid_status=[200],
            response_field="",
            response_value="OK",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 5.3 Medium",
            impact_desc="Geocoding API — attacker can consume quota at $5/1k requests",
        ),
        Endpoint(
            "Places Nearby Search",
            url="https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=0,0&radius=1&key=***",
            billable=True, cost_per_call=0.032, cost_unit="request",
            monthly_volume_desc="1M req/month → ~$32,000/month",
            valid_status=[200],
            response_field="",
            response_value="ZERO_RESULTS",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 5.3 Medium",
            impact_desc="Places API — highest-cost Maps API, $32/1k requests",
        ),
        Endpoint(
            "Directions",
            url="https://maps.googleapis.com/maps/api/directions/json?origin=Paris&destination=Lyon&key=***",
            billable=True, cost_per_call=0.005, cost_unit="request",
            monthly_volume_desc="1M req/month → ~$5,000/month",
            valid_status=[200],
            response_field="",
            response_value="OK",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 5.3 Medium",
            impact_desc="Directions API — billable at $5/1k requests",
        ),
    ],
    "🔑 Key Metadata": [
        Endpoint(
            "Key Info (apikeys API)",
            url="https://apikeys.googleapis.com/v2/keys?key={KEY}&pageSize=1",
            valid_status=[200, 404],
            response_field="keys",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3 Medium",
            impact_desc="API key can query own metadata — may reveal project, restrictions, creation date",
        ),
    ],
    "🤖 Generative AI (Gemini)": [
        Endpoint(
            "Gemini — List Models",
            url="https://generativelanguage.googleapis.com/v1/models?key={KEY}",
            valid_status=[200],
            response_field="models",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 5.3 Medium",
            impact_desc="Gemini API accessible — can generate content at your expense",
        ),
        Endpoint(
            "Gemini — Generate (gemini-2.5-flash)",
            method="POST",
            url="https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={KEY}",
            headers={"Content-Type": "application/json"},
            body={"contents": [{"parts": [{"text": "Say 'hello' in one word."}]}]},
            valid_status=[200],
            response_field="candidates",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 5.3 Medium",
            impact_desc="Full generation access — attacker can consume AI quota indefinitely",
        ),
    ],
    "☁️ Cloud Resource Manager": [
        Endpoint(
            "List Projects",
            url="https://cloudresourcemanager.googleapis.com/v1/projects?key={KEY}",
            valid_status=[200],
            response_field="projects",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 HIGH",
            impact_desc="Lists ALL GCP projects! Full project enumeration.",
        ),
    ],
    "🗄️ Cloud Storage": [
        Endpoint(
            "Storage — Test Bucket Access",
            url="https://storage.googleapis.com/storage/v1/b?key={KEY}&project={PROJECT}",
            valid_status=[200, 403],
            response_field="items",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 8.6 HIGH",
            impact_desc="Storage API — may allow listing/reading buckets if project scope allows",
        ),
    ],
    "💻 Compute Engine": [
        Endpoint(
            "Compute — Aggregated List",
            url="https://compute.googleapis.com/compute/v1/projects/{PROJECT}/aggregated/instances?key={KEY}",
            valid_status=[200, 403],
            response_field="items",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 HIGH",
            impact_desc="Lists compute instances across zones — infrastructure enumeration",
        ),
    ],
    "🔥 Firebase": [
        Endpoint(
            "Firebase — List Projects",
            url="https://firebase.googleapis.com/v1beta1/projects?key={KEY}",
            valid_status=[200],
            response_field="results",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 8.6 HIGH",
            impact_desc="Enumerates Firebase projects — may expose app configs and databases",
        ),
        Endpoint(
            "Firestore — List Databases",
            url="https://firestore.googleapis.com/v1/projects/{PROJECT}/databases?key={KEY}",
            valid_status=[200, 403],
            response_field="databases",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 8.6 HIGH",
            impact_desc="Lists Firestore databases — may allow reading/writing user data",
        ),
    ],
    "🔐 IAM": [
        Endpoint(
            "IAM — List Roles",
            url="https://iam.googleapis.com/v1/roles?key={KEY}",
            valid_status=[200],
            response_field="roles",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 4.3 Medium",
            impact_desc="Can list IAM roles — privilege enumeration, pre-attack recon",
        ),
        Endpoint(
            "IAM — List Service Accounts",
            url="https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts?key={KEY}",
            valid_status=[200, 403],
            response_field="accounts",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 HIGH",
            impact_desc="Lists service accounts — exposes email addresses and IDs",
        ),
    ],
    "⚡ Cloud Functions": [
        Endpoint(
            "Cloud Functions — List",
            url="https://cloudfunctions.googleapis.com/v1/projects/{PROJECT}/locations/-/functions?key={KEY}",
            valid_status=[200, 403],
            response_field="functions",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 HIGH",
            impact_desc="Lists cloud functions — exposes entry points and source repos",
        ),
    ],
    "🧠 Cloud AI (Vertex)": [
        Endpoint(
            "Vertex AI — List Models",
            url="https://aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/-/models?key={KEY}",
            valid_status=[200, 403],
            response_field="models",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N → 5.4 Medium",
            impact_desc="Vertex AI accessible — may allow training/inference with company models",
        ),
    ],
    "📺 YouTube": [
        Endpoint(
            "YouTube — Video List",
            url="https://www.googleapis.com/youtube/v3/videos?part=snippet&id=dQw4w9WgXcQ&key={KEY}",
            valid_status=[200],
            response_field="items",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 4.3 Medium",
            impact_desc="YouTube Data API — quota-based billing, 10k units/day default",
        ),
    ],
    "🔍 Google Custom Search": [
        Endpoint(
            "Custom Search",
            url="https://www.googleapis.com/customsearch/v1?q=test&key={KEY}",
            valid_status=[200, 403],
            response_field="items",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 4.3 Medium",
            impact_desc="Custom Search JSON API — 100 queries/day free, then $5/1k",
        ),
    ],
    "📊 Analytics": [
        Endpoint(
            "Analytics — Account Summaries",
            url="https://analyticsadmin.googleapis.com/v1alpha/accountSummaries?key={KEY}",
            valid_status=[200, 403],
            response_field="accountSummaries",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 HIGH",
            impact_desc="Lists Google Analytics accounts — exposes client list and metrics",
        ),
    ],
    "📧 Gmail": [
        Endpoint(
            "Gmail — Profile",
            url="https://gmail.googleapis.com/gmail/v1/users/me/profile?key={KEY}",
            valid_status=[200, 403],
            response_field="emailAddress",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 HIGH",
            impact_desc="Gmail API access — may allow reading email metadata and content",
        ),
    ],
    "📅 Calendar": [
        Endpoint(
            "Calendar — List",
            url="https://www.googleapis.com/calendar/v3/users/me/calendarList?key={KEY}",
            valid_status=[200, 403],
            response_field="items",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 HIGH",
            impact_desc="Calendar API — exposes calendar names, events, and attendees",
        ),
    ],
    "💬 Cloud Natural Language": [
        Endpoint(
            "NL API — Analyze Sentiment",
            method="POST",
            url="https://language.googleapis.com/v1/documents:analyzeSentiment?key={KEY}",
            headers={"Content-Type": "application/json"},
            body={"document": {"type": "PLAIN_TEXT", "content": "Hello world"}, "encodingType": "UTF8"},
            valid_status=[200],
            response_field="documentSentiment",
            cvss_if_valid="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 5.3 Medium",
            impact_desc="Natural Language API — billable, can consume quota",
        ),
    ],
}


# ── CVSS Parser ────────────────────────────────────────────────────────────
def parse_cvss(cvss_str):
    """Extract score and severity from CVSS string."""
    for part in cvss_str.split("→"):
        part = part.strip()
        try:
            score = float(part.split()[0])
            if score >= 9.0: return score, "CRITICAL"
            elif score >= 7.0: return score, "HIGH"
            elif score >= 4.0: return score, "MEDIUM"
            else: return score, "LOW"
        except ValueError:
            continue
    return 0.0, "INFO"


# ── Cost Calculator ─────────────────────────────────────────────────────────
def calc_cost_impact(ep, key, session):
    """Estimate cost impact for billable endpoints."""
    scenarios = [
        (10_000, "hour"),
        (100_000, "day"),
        (1_000_000, "month"),
    ]
    lines = []
    for volume, period in scenarios:
        cost = volume * ep.cost_per_call
        if cost >= 1000:
            cost_str = f"${cost:,.0f}"
        else:
            cost_str = f"${cost:.2f}"
        lines.append(f"     {volume:,} req/{period} → {cost_str}")
    return lines


# ── Core Tester ─────────────────────────────────────────────────────────────
def test_endpoint(ep: Endpoint, key: str, referer: str = "") -> dict:
    """Test one endpoint against the API key, return result dict."""
    global PROJECT_ID
    url = ep.url.replace("{KEY}", key)
    # Substitute discovered project ID, or fall back to placeholder
    if "{PROJECT}" in url:
        if PROJECT_ID:
            url = url.replace("{PROJECT}", PROJECT_ID)
        else:
            url = url.replace("{PROJECT}", "test")
    headers = dict(ep.headers or {})
    if referer:
        headers["Referer"] = referer
    kwargs = {"timeout": 12, "headers": headers}
    if ep.method == "POST":
        kwargs["json"] = ep.body
    try:
        if ep.method == "GET":
            r = requests.get(url, **kwargs)
        else:
            r = requests.post(url, **kwargs)
        status = r.status_code
        body = ""
        js = {}
        try:
            js = r.json()
            body = json.dumps(js)[:500]
        except Exception:
            body = r.text[:500]

        # Determine validity
        valid = status in ep.valid_status

        # If the response contains an "error" field, it's NOT a valid access
        # (Google APIs return 200/403 with {"error": ...} when the key lacks permissions)
        if valid and js.get("error"):
            valid = False
        elif valid and ep.response_field:
            valid = bool(js.get(ep.response_field))
        elif valid and ep.response_value:
            # Check for response_value in the JSON (e.g., status="OK" for Maps)
            valid = (js.get("status", "") == ep.response_value)

        error = js.get("error", {})
        error_code = error.get("status", "") if isinstance(error, dict) else ""
        error_msg = (error.get("message", "") if isinstance(error, dict) else str(error))[:120]

        # Extract project ID from error messages (e.g., "project 915150313882")
        if not PROJECT_ID:
            m = PROJECT_RE.search(error_msg)
            if m:
                PROJECT_ID = m.group(1)

        return {
            "status_code": status,
            "valid": valid,
            "error_code": error_code,
            "error_msg": error_msg,
            "body_preview": body,
        }
    except requests.exceptions.Timeout:
        return {"status_code": 0, "valid": False, "error_msg": "TIMEOUT"}
    except Exception as e:
        return {"status_code": 0, "valid": False, "error_msg": str(e)[:100]}


# ── Display Helpers ─────────────────────────────────────────────────────────
def print_banner(key, referer=""):
    masked = key[:12] + "..." + key[-4:] if len(key) > 16 else key[:8] + "..."
    ESC = "\033[35m"
    BC = "\033[1;96m"
    NN = "\033[0m"
    B = BC + "+--------------------------------------------------------------+" + NN
    E = BC + "|                                                              |" + NN
    art = [
        BC + "|                   _     _                   _                |" + NN,
        BC + "|                  | |   (_)                 | |               |" + NN,
        BC + "|        __ _  __ _| |__  _   _ __  _ __ ___ | |__   ___       |" + NN,
        BC + r"|       / _` |/ _` | '_ \| | | '_ \| '__/ _ \| '_ \ / _ \      |" + NN,
        BC + "|      | (_| | (_| | |_) | | | |_) | | | (_) | |_) |  __/      |" + NN,
        BC + r"|       \__, |\__,_|_.__/|_| | .__/|_|  \___/|_.__/ \___|      |" + NN,
        BC + "|        __/ |               | |                               |" + NN,
        BC + "|       |___/                |_|                               |" + NN,
    ]
    title = BC + "|     " + BC + "mys3quel" + BC + "  \u2014  Google API Key Probe                        |" + NN
    key_line = BC + f"|     Key: {masked:<51} |" + NN
    ref_line = BC + f"|     Referer: {referer:<47} |" + NN if referer else ""

    print(B)
    print(E)
    for line in art:
        print(line)
    print(E)
    print(title)
    print(E)
    print(key_line)
    if ref_line:
        print(ref_line)
    print(B)

def print_result(ep_name, result, ep):
    status = result["status_code"]
    valid = result["valid"]
    color = C["G"]
    symbol = "✓"
    tag = "VALID"

    if status == 0:
        color = C["R"]; symbol = "✗"; tag = "ERROR"
    elif status in (400, 401, 403, 404, 405):
        color = C["D"]; symbol = "○"; tag = "DENIED"
    elif not valid and status == 200:
        color = C["D"]; symbol = "○"; tag = "NO DATA"
    elif not valid:
        color = C["D"]; symbol = "○"; tag = "NO DATA"
    elif valid:
        color = C["BG"]; symbol = "🔥"; tag = "ACCESS"

    print(f"  {color}{symbol}{C['N']} {ep_name:<45} {color}{tag:<8}{C['N']}", end="")

    if valid:
        score, severity = parse_cvss(ep.cvss_if_valid)
        sev_color = {"CRITICAL": C["BR"], "HIGH": C["R"], "MEDIUM": C["Y"], "LOW": C["G"], "INFO": C["D"]}
        sc = sev_color.get(severity, C["N"])
        print(f" {sc}CVSS {score:.1f} ({severity}){C['N']}")
        print(f"     {C['D']}▸ {ep.impact_desc}{C['N']}")

        if ep.billable:
            print(f"     {C['BC']}💲 Cost per {ep.cost_unit}: ${ep.cost_per_call:.4f}{C['N']}")
            for line in calc_cost_impact(ep, "", None):
                print(f"     {C['D']}{line}{C['N']}")

        # Save to summary
        SUMMARY.append({
            "endpoint": ep_name,
            "service": ep.url.split("/")[2] if "//" in ep.url else "",
            "status": status,
            "cvss": ep.cvss_if_valid,
            "score": score,
            "severity": severity,
            "impact": ep.impact_desc,
            "billable": ep.billable,
            "cost_per_call": ep.cost_per_call if ep.billable else 0,
            "body_preview": result.get("body_preview", "")[:200],
        })
    else:
        err = result.get("error_msg", "")
        if err:
            print(f" {C['D']}({err[:60]}){C['N']}")
        else:
            print()


def print_summary():
    valid_count = len([s for s in SUMMARY if s["severity"] != "INFO"])
    if valid_count == 0:
        print(f"\n{C['G']}✅ No exploitable endpoints found — key may be restricted or invalid.{C['N']}\n")
        return

    print(f"\n{C['BC']}╔══════════════════════════════════════════════════════════╗")
    print(f"║  SUMMARY — {valid_count} exploitable endpoint(s) found               ║")
    print(f"╚══════════════════════════════════════════════════════════╝{C['N']}\n")

    print(f"  {'ENDPOINT':<45} {'STATUS':<8} {'CVSS':<22} {'IMPACT'}")
    print(f"  {'─'*45} {'─'*8} {'─'*22} {'─'*30}")
    for s in sorted(SUMMARY, key=lambda x: x.get("score", 0), reverse=True):
        score, sev = s["score"], s["severity"]
        sev_color = {"CRITICAL": C["BR"], "HIGH": C["R"], "MEDIUM": C["Y"], "LOW": C["G"]}.get(sev, C["N"])
        impact = s["impact"][:50]
        billable = " 💲" if s["billable"] else ""
        print(f"  {s['endpoint']:<45} {sev_color}{sev:<8}{C['N']} {sev_color}CVSS {score:.1f} ({sev}){billable:<4}{C['N']}  {impact}")

    # Top vulnerability
    top = max(SUMMARY, key=lambda x: x.get("score", 0))
    print(f"\n  {C['BR']}🏆 TOP FINDING:{C['N']} {top['endpoint']} → {top['severity']} ({top['score']})")

    # Total billable cost
    billable = [s for s in SUMMARY if s["billable"]]
    if billable:
        hourly = sum(s["cost_per_call"] * 10000 for s in billable)
        daily = sum(s["cost_per_call"] * 100000 for s in billable)
        monthly = sum(s["cost_per_call"] * 1000000 for s in billable)
        print(f"""\n  {C['BY']}💲 BILLABLE IMPACT (combined):{C['N']}
     {C['D']}10k req/hr  → ${hourly:,.2f}{C['N']}
     {C['D']}100k req/day → ${daily:,.2f}{C['N']}
     {C['D']}1M req/month → ${monthly:,.2f}{C['N']}""")

    print()


# ── Key Extractor ────────────────────────────────────────────────────────────
KEY_REGEX = re.compile(r"AIza[0-9A-Za-z_-]{35}")

def extract_keys(text: str) -> list:
    """Extract unique Google API keys from arbitrary text, preserving order."""
    seen = set()
    keys = []
    for m in KEY_REGEX.finditer(text):
        k = m.group(0)
        if k not in seen:
            seen.add(k)
            keys.append(k)
    return keys


def run_probe(key: str, referer: str, service_filter: str = "") -> int:
    """Run all endpoint tests for a key. Returns count of exploitable findings."""
    global SUMMARY
    SUMMARY = []
    print_banner(key, referer)
    tested = 0

    for service_name, endpoints in SERVICES.items():
        if service_filter and service_filter.lower() not in service_name.lower():
            continue
        print(f"\n{C['BC']}── {service_name} ──{C['N']}")
        for ep in endpoints:
            with Progress(f"Testing {ep.name}...") as p:
                result = test_endpoint(ep, key, referer)
            print_result(ep.name, result, ep)
            tested += 1
            time.sleep(2.0 if ep.billable else 0.5)

    print_summary()
    return len([s for s in SUMMARY if s["severity"] != "INFO"])


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Google API Key Probe")
    parser.add_argument("key", nargs="?", help="Google API key (AIza...), or paste multi-key text interactively")
    parser.add_argument("--json", help="Save results to JSON file")
    parser.add_argument("--service", help="Only test a specific service group")
    parser.add_argument("--referer", help="Referer header to send (bypasses IP/domain restrictions on some keys)")
    args = parser.parse_args()

    # ── Determine referer ──────────────────────────────────────────────────
    referer = args.referer or ""
    if not referer and not args.key:
        # Interactive mode: ask for referer (default: no)
        ans = input(f"\n{C['BC']}[?] Add Referer header? {C['D']}(domain to restrict-spoof, or Enter to skip){C['N']}: ").strip()
        if ans:
            referer = ans

    # ── Determine key(s) ───────────────────────────────────────────────────
    keys_to_test = []

    if args.key:
        # CLI argument — could be raw key or copy-paste with multiple keys
        extracted = extract_keys(args.key)
        if len(extracted) > 1:
            # Multiple keys detected in CLI arg text
            keys_to_test = extracted
            print(f"\n{C['BC']}[i] Detected {len(keys_to_test)} unique keys in input{C['N']}")
        elif len(extracted) == 1:
            keys_to_test = [args.key.strip()]
        else:
            keys_to_test = [args.key.strip()]  # maybe a non-standard key format
    else:
        # Interactive paste — Ctrl+D to finish (preserves newlines in pasted text)
        print(f"\n{C['BC']}[?] Paste Google API key(s) or full search output:{C['N']}")
        print(f"    {C['D']}(paste text, then press Ctrl+D to finish){C['N']}")
        raw_input = sys.stdin.read().strip()
        if not raw_input:
            print(f"{C['R']}[!] No input provided.{C['N']}")
            sys.exit(1)

        extracted = extract_keys(raw_input)
        if not extracted:
            # No AIza keys found — treat as single key
            keys_to_test = [raw_input]
        else:
            keys_to_test = extracted
            if len(extracted) > 1:
                print(f"\n{C['BC']}[i] Detected {len(extracted)} unique Google API keys:{C['N']}\n")
                for i, k in enumerate(extracted, 1):
                    # Show context snippet around the key
                    idx = raw_input.find(k)
                    ctx = raw_input[max(0, idx-30):idx+len(k)+30].replace("\n", " ")
                    print(f"  {C['BY']}{i}.{C['N']} {k}  {C['D']}…{ctx}…{C['N']}")
                print(f"\n{C['BC']}[*] Testing all {len(extracted)} keys sequentially...{C['N']}")
            else:
                print(f"\n{C['BC']}[i] Detected 1 Google API key{C['N']}")

    if not keys_to_test:
        print(f"{C['R']}[!] No keys to test.{C['N']}")
        sys.exit(1)

    # ── Run probe for each key ──────────────────────────────────────────────
    all_findings = []
    for ki, key in enumerate(keys_to_test):
        if len(keys_to_test) > 1:
            masked = key[:12] + "..." + key[-4:] if len(key) > 16 else key[:8] + "..."
            print(f"\n\n{C['BC']}══════════ Key {ki+1}/{len(keys_to_test)}: {masked} ══════════{C['N']}")
        findings = run_probe(key, referer, args.service or "")
        all_findings.append({"key": key, "findings": findings})

    # ── Multi-key recap ────────────────────────────────────────────────────
    if len(keys_to_test) > 1:
        print(f"\n\n{C['BC']}╔══════════════════════════════════════════════════════════╗")
        print(f"║  MULTI-KEY RECAP                                       ║")
        print(f"╚══════════════════════════════════════════════════════════╝{C['N']}\n")
        for r in all_findings:
            masked = r["key"][:12] + "..." + r["key"][-4:] if len(r["key"]) > 16 else r["key"][:8] + "..."
            if r["findings"] > 0:
                print(f"  {C['BG']}🔥{C['N']} {masked}  →  {C['R']}{r['findings']} exploitable{C['N']}")
            else:
                print(f"  {C['D']}○{C['N']} {masked}  →  no findings")

    # ── JSON export (single key only for now) ──────────────────────────────
    if args.json and len(keys_to_test) == 1:
        with open(args.json, "w") as f:
            json.dump({
                "key_masked": keys_to_test[0][:12] + "..." + keys_to_test[0][-4:] if len(keys_to_test[0]) > 16 else keys_to_test[0][:8] + "...",
                "total_endpoints_tested": sum(len(v) for v in SERVICES.values()),
                "exploitable_endpoints": all_findings[0]["findings"] if all_findings else 0,
                "findings": SUMMARY,
            }, f, indent=2)
        print(f"\n{C['G']}[+] Report saved to {args.json}{C['N']}")


if __name__ == "__main__":
    main()
