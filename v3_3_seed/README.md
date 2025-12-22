# MSN/Taboola Watchdog (v3.3 seed)

This bundle gives you a **one-file Playwright collector** + **export-ready evidence pack** layout.

## What you get
- A budgeted crawler (ex: 10–20 pages/day)
- Per-page evidence pack:
  - `full.png` + `viewport.png`
  - `page.har` (HAR network capture)
  - `requests.json` / `responses.json` / `console.json`
  - `redirect_chain.json` (main document redirects)
  - `taboola_extract.json` (widget + creative cards)
  - `widgets/widget_*.png` (best-effort widget screenshots)
  - `license_hits.json` (keyword hits in page + ad copy)
- `summary.csv` / `summary.json` for triage
- Optional `urlscan` submissions (OFF by default)

## Install
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
```

## Run (daily budget example)
```bash
python watchdog_collect.py --config config.sample.json --out out --page-budget 20 --headless
```

## urlscan toggle (recommended for redirect chains without clicking ads)
```bash
# Windows PowerShell
$env:URLSCAN_API_KEY="..."
python watchdog_collect.py --urlscan --config config.sample.json
```

## Operational guidance
- **Cadence**: 10–20 URLs/day is plenty.
- **No ad clicks**: default behavior is “observe, don’t poke the bear.”
- **Proxies**: Prefer *no proxy* or a straightforward datacenter proxy.

## Evidence packs & escalation
Use the templates in `templates/` to file reports with Taboola, Microsoft Advertising, and regulators.
