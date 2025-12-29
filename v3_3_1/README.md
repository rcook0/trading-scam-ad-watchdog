# trading-scam-ad-watchdog (v3.3.1)

Evidence collector for trading/investment scam ads (MSN/Taboola first), generating export-ready packs for platform + regulator escalations.

## What’s new in v3.3.1
- **Landing domain clustering**
- **Heuristic risk scoring**
  - configurable regex signals (ad copy patterns)
  - configurable “higher-risk TLD weightings”
  - brand-token vs registrable-domain mismatch heuristic
  - url-shortener detection
  - small uncertainty bump if only tracking click URLs are available

This is triage. It helps you prioritize which creatives/domains to escalate first.

## Install
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
```

## Run
```bash
python watchdog_collect.py --config config.sample.json --out out --page-budget 20 --headless
```

## Accurate landing domains (recommended)
By default we do **not click ads**. For landing domains, enable urlscan:
```bash
# PowerShell
$env:URLSCAN_API_KEY="..."
python watchdog_collect.py --urlscan --config config.sample.json
```

If you want clustering to use the *resolved landing page* during the same run:
- set: `"urlscan": { "poll_for_result": true }`

## Outputs
Per run (`out/runs/<run_id>/`):
- `targets/<target_id>/...` evidence packs (screenshots, HAR, logs, creatives extract)
- `creatives_flat.jsonl` + `creatives_flat.csv`
- `landing_clusters.json` + `landing_clusters.csv`
- `risk_report.json`
- optional: `<run_id>.zip`

## Safety posture
- **Observe, don’t click** (default).
- Keep cadence low (10–20 URLs/day).
- Avoid stealth/residential proxy setups unless you have explicit compliance reasons.
