# gapi-probe — Google API Key Tester

Tests a Google API key against 21 endpoints across 16 Google Cloud services. Real-time colored output, CVSS estimation, cost impact calculator.

## Install

```bash
pip install -r requirements.txt
```

## Usage

### Single key

```bash
python3 gapi_probe.py AIzaSy...
```

### With Referer header (bypass HTTP referrer restrictions)

```bash
python3 gapi_probe.py AIzaSy... --referer "https://www.target.com/"
```

### Filter by service

```bash
python3 gapi_probe.py AIzaSy... --service gemini
python3 gapi_probe.py AIzaSy... --service maps
```

### Export JSON report

```bash
python3 gapi_probe.py AIzaSy... --json report.json
```

### Interactive multi-key (bulk testing)

```bash
python3 gapi_probe.py
# → Optional: paste Referer domain (Enter to skip)
# → Paste text containing AIza keys (Ctrl+D to finish)
# → All unique keys auto-extracted, deduplicated, and tested sequentially
```

Also works via CLI pipe:

```bash
pbpaste | python3 gapi_probe.py --referer "https://target.com"
cat search_results.txt | python3 gapi_probe.py
```

## Services tested

| # | Service | Key endpoints |
|---|---------|--------------|
| 🔑 | Key Metadata | Key info (apikeys API) |
| 🤖 | Generative AI (Gemini) | List models, generate content |
| ☁️ | Cloud Resource Manager | List projects |
| 🗄️ | Cloud Storage | Bucket access test |
| 💻 | Compute Engine | Aggregated instances list |
| 🔥 | Firebase | List projects, Firestore databases |
| 🔐 | IAM | List roles, list service accounts |
| ⚡ | Cloud Functions | List functions |
| 🧠 | Cloud AI (Vertex) | List models |
| 🗺️ | Maps (billable) | Geocoding, Places, Directions |
| 📺 | YouTube | Video list |
| 🔍 | Custom Search | Query test |
| 📊 | Analytics | Account summaries |
| 📧 | Gmail | Profile endpoint |
| 📅 | Calendar | Calendar list |
| 💬 | Cloud Natural Language | Analyze sentiment |

## Features

- **Project ID auto-extraction** — Gemini errors reveal the GCP project number, automatically used for Storage, Compute, Firebase, IAM, Cloud Functions, and Vertex AI probes
- **Smart validity detection** — ignores `{"error": ...}` bodies (Google returns 200/403 with errors when key lacks permissions), eliminates false positives
- **Referer spoofing** — `--referer` adds `Referer` header to all requests, bypassing HTTP referrer restrictions on API keys
- **Multi-key extraction** — regex `AIza[0-9A-Za-z_-]{35}` finds all keys in pasted text, deduplicates, and tests each one with a final recap table
- **Billable impact estimation** — for Maps/Geocoding/Places: calculates $/hr, $/day, $/month at 10k/100k/1M request volumes
- **CVSS scoring** — each finding auto-scored from INFO to CRITICAL based on endpoint sensitivity
