#!/usr/bin/env python3
"""
Trading Scam Ad Watchdog — v3.3.1 collector (single file)

Core idea:
- Crawl a small, budgeted set of MSN section/locales pages.
- Capture an evidence pack (screenshots, HAR, logs, redirect chain).
- Extract Taboola-ish "creative cards".
- NEW v3.3.1: landing-domain clustering + heuristic risk scoring.

Important:
- Default behavior is OBSERVE ONLY (no ad clicks).
- For accurate landing domains, enable urlscan (recommended) and optionally poll for results.

This is a triage tool, not an oracle.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import random
import re
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    import tldextract  # type: ignore
except Exception:  # pragma: no cover
    tldextract = None  # type: ignore

from playwright.sync_api import sync_playwright, TimeoutError as PwTimeoutError  # type: ignore


DEFAULT_CONFIG: Dict[str, Any] = {
    "run_profile": {
        "page_budget": 20,
        "min_delay_ms": 5000,
        "max_delay_ms": 15000,
        "headless": True,
        "stabilize_ms": 7000,
        "timeout_ms": 45000,
        "zip": True,
        "auto_consent": True
    },
    "targets": [],
    "detection": {
        "taboola_container_css": [
            "[id*='taboola' i]",
            "[class*='taboola' i]",
            "[data-taboola]",
            "script[src*='taboola' i]"
        ],
        "max_creatives_per_target": 30,
        "license_keyword_regex": (
            r"\\b("
            r"fca|finanstilsynet|asa|asic|cysec|sec\\b|cftc|nfa|fsa\\b|"
            r"regulated|authori[sz]ed|licen[cs]e(d)?|registered"
            r")\\b"
        )
    },
    "urlscan": {
        "enabled": False,
        "visibility": "public",
        "tags": ["trading-scam-ad-watchdog"],
        "max_submissions_per_run": 10,
        "poll_for_result": False,
        "poll_initial_wait_s": 10,
        "poll_interval_s": 2,
        "poll_timeout_s": 60
    },
    "risk": {
        "enabled": True,
        "high_risk_threshold": 30,
        "medium_risk_threshold": 15,
        "weights": {
            "tld": 12,
            "keyword_hit": 6,
            "brand_mismatch": 8,
            "shortener": 20,
            "regulator_name_drop": 6,
            "unresolved_tracking_click_url": 5
        },
        "tld_weights": {
            ".top": 18,
            ".xyz": 12,
            ".click": 20,
            ".site": 12,
            ".online": 10,
            ".live": 12,
            ".icu": 15,
            ".info": 8
        },
        "url_shorteners": ["bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly"],
        "tracking_domains": ["trc.taboola.com", "taboola.com", "taboolasyndication.com", "outbrain.com", "zemanta.com"],
        "keyword_regexes": [
            "(?i)\\bguaranteed\\b",
            "(?i)\\bprofit\\b",
            "(?i)\\bget rich\\b",
            "(?i)\\bautomated\\s+trading\\b|\\btrading\\s+bot\\b",
            "(?i)\\bcrypto\\b|\\bbitcoin\\b",
            "(?i)\\bcelebrity\\b|\\bexclusive\\b|\\bbreaking\\b",
            "(?i)\\bno\\s+risk\\b|\\brisk\\-free\\b",
        ],
        "brand_stopwords": [
            "the","a","an","and","or","to","of","in","on","for","with","from","by",
            "news","today","report","reveals","this","that","you","your","their","our",
            "how","why","what","when","where","new","top","best","all","now"
        ]
    }
}


def utc_now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def safe_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")[:80] or "target"


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def read_state(state_path: Path) -> Dict[str, Any]:
    if state_path.exists():
        try:
            return load_json(state_path)
        except Exception:
            pass
    return {"cursor": 0, "last_run_utc": None}


def choose_targets_round_robin(targets: List[Dict[str, Any]], state: Dict[str, Any], budget: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if not targets:
        return [], state
    cursor = int(state.get("cursor", 0)) % len(targets)
    chosen: List[Dict[str, Any]] = []
    for _ in range(min(budget, len(targets))):
        chosen.append(targets[cursor])
        cursor = (cursor + 1) % len(targets)
    state["cursor"] = cursor
    return chosen, state


def zip_dir(src_dir: Path, zip_path: Path) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in src_dir.rglob("*"):
            if p.is_file():
                z.write(p, arcname=str(p.relative_to(src_dir)))


def jitter_sleep(min_ms: int, max_ms: int) -> None:
    lo = max(0, int(min_ms))
    hi = max(lo, int(max_ms))
    time.sleep(random.uniform(lo, hi) / 1000.0)


def redact_url(url: str, keep_query: bool = False) -> str:
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(url)
        if keep_query:
            return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except Exception:
        return url


def get_host(url: str) -> str:
    try:
        from urllib.parse import urlsplit
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def get_registrable_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    if tldextract:
        ext = tldextract.extract(host)  # type: ignore
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        if ext.domain:
            return ext.domain.lower()
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def tld_of_domain(reg_domain: str) -> str:
    reg_domain = (reg_domain or "").lower()
    if not reg_domain or "." not in reg_domain:
        return ""
    return "." + reg_domain.split(".")[-1]


def guess_cookie_consent(page) -> bool:
    patterns = [re.compile(r"\\baccept\\b", re.I), re.compile(r"\\bagree\\b", re.I), re.compile(r"\\ballow\\b", re.I)]
    try:
        for pat in patterns:
            btn = page.get_by_role("button", name=pat)
            if btn and btn.count() > 0:
                btn.first.click(timeout=1500)
                return True
    except Exception:
        pass
    try:
        for pat in patterns:
            loc = page.locator("button", has_text=pat)
            if loc.count() > 0:
                loc.first.click(timeout=1500)
                return True
    except Exception:
        pass
    return False


def extract_taboola_like(page, container_css: List[str], max_creatives: int) -> Dict[str, Any]:
    css_union = ", ".join(container_css) if container_css else "[id*='taboola' i], [class*='taboola' i], [data-taboola]"
    js = r"""
    (cssUnion, maxCreatives) => {
      const containers = Array.from(document.querySelectorAll(cssUnion))
        .filter(el => el && el.getBoundingClientRect && el.getBoundingClientRect().height > 20);

      const uniq = new Set();
      const widgets = [];

      function cleanText(s) {
        if (!s) return "";
        return String(s).replace(/\\s+/g, " ").trim().slice(0, 280);
      }

      function pickBestText(a) {
        return cleanText(a.innerText || a.getAttribute("title") || a.getAttribute("aria-label") || "");
      }

      for (const c of containers.slice(0, 10)) {
        const links = Array.from(c.querySelectorAll("a[href]"));
        const creatives = [];
        for (const a of links) {
          const href = a.getAttribute("href");
          if (!href) continue;
          const abs = new URL(href, document.baseURI).toString();
          if (uniq.has(abs)) continue;
          uniq.add(abs);

          const img = a.querySelector("img");
          const imgSrc = img ? (img.currentSrc || img.src || "") : "";
          const title = pickBestText(a);
          const rect = a.getBoundingClientRect();
          if ((rect.width || 0) < 30 || (rect.height || 0) < 20) continue;

          creatives.push({
            href: abs,
            title,
            img: imgSrc,
            rect: { x: rect.x, y: rect.y, w: rect.width, h: rect.height }
          });
          if (creatives.length >= maxCreatives) break;
        }

        const cRect = c.getBoundingClientRect();
        widgets.push({
          container: {
            tag: c.tagName,
            id: c.id || null,
            className: (c.className && String(c.className).slice(0, 200)) || null,
            rect: { x: cRect.x, y: cRect.y, w: cRect.width, h: cRect.height }
          },
          creatives
        });

        if (widgets.reduce((n, w) => n + w.creatives.length, 0) >= maxCreatives) break;
      }

      const hasTaboolaSignal =
        containers.length > 0 ||
        !!document.querySelector("script[src*='taboola' i]") ||
        (typeof window._taboola !== "undefined");

      return { hasTaboolaSignal, widgetCount: widgets.length, widgets };
    }
    """
    return page.evaluate(js, css_union, int(max_creatives))


def build_redirect_chain(response) -> List[Dict[str, Any]]:
    chain: List[Dict[str, Any]] = []
    try:
        req = response.request
        r = req
        while r:
            chain.append({"url": r.url, "method": r.method, "resource_type": r.resource_type})
            r = r.redirected_from
        chain.reverse()
        chain[-1]["status"] = response.status
        chain[-1]["ok"] = response.ok
    except Exception:
        pass
    return chain


def keyword_hits(text: str, regex: str) -> List[str]:
    if not text:
        return []
    try:
        pat = re.compile(regex, re.I)
        return sorted(set(m.group(0) for m in pat.finditer(text)))[:50]
    except Exception:
        return []


def pick_brand_tokens(title: str, stopwords: List[str]) -> List[str]:
    if not title:
        return []
    stop = set(w.lower() for w in stopwords)
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9\\-]{2,}", title)
    cands = []
    for t in tokens:
        if t.lower() in stop:
            continue
        if (re.search(r"[A-Z].*[A-Z]", t) or t.isupper() or (t[0].isupper() and len(t) >= 5)):
            cands.append(t)
    cands = sorted(set(cands), key=lambda x: (-len(x), x))
    return cands[:5]


def compute_risk(
    title: str,
    click_reg_domain: str,
    landing_reg_domain: str,
    license_hits: List[str],
    risk_cfg: Dict[str, Any]
) -> Tuple[int, List[str], Dict[str, Any]]:
    if not risk_cfg.get("enabled", True):
        return 0, [], {}

    weights = risk_cfg.get("weights", {})
    tld_weights = risk_cfg.get("tld_weights", {})
    shorteners = set((risk_cfg.get("url_shorteners", []) or []))
    tracking = set((risk_cfg.get("tracking_domains", []) or []))
    keyword_res = [re.compile(rx) for rx in (risk_cfg.get("keyword_regexes", []) or [])]
    stopwords = (risk_cfg.get("brand_stopwords", []) or [])

    score = 0
    reasons: List[str] = []
    feats: Dict[str, Any] = {}

    reg_domain = landing_reg_domain or click_reg_domain
    feats["registrable_domain"] = reg_domain
    feats["landing_reg_domain"] = landing_reg_domain or ""
    feats["click_reg_domain"] = click_reg_domain or ""

    tld = tld_of_domain(reg_domain)
    feats["tld"] = tld
    if tld:
        add = int(tld_weights.get(tld, 0))
        if add:
            score += add
            reasons.append(f"tld_weight({tld})+{add}")

    if reg_domain in shorteners:
        add = int(weights.get("shortener", 20))
        score += add
        reasons.append(f"url_shortener({reg_domain})+{add}")

    kw_hits = []
    for pat in keyword_res:
        if title and pat.search(title):
            kw_hits.append(pat.pattern)
    if kw_hits:
        add = int(weights.get("keyword_hit", 6)) * len(kw_hits)
        score += add
        reasons.append(f"title_keywords({len(kw_hits)})+{add}")
    feats["keyword_hit_count"] = len(kw_hits)

    reg_hits = [h for h in (license_hits or []) if title and re.search(re.escape(h), title, re.I)]
    if reg_hits:
        add = int(weights.get("regulator_name_drop", 6))
        score += add
        reasons.append(f"regulator_name_drop+{add}")
    feats["regulator_name_drop"] = bool(reg_hits)

    brand_tokens = pick_brand_tokens(title or "", stopwords)
    feats["brand_tokens"] = brand_tokens
    if brand_tokens and reg_domain:
        dom = reg_domain.lower()
        mismatched = all(bt.lower() not in dom for bt in brand_tokens[:2])
        if mismatched:
            add = int(weights.get("brand_mismatch", 8))
            score += add
            reasons.append(f"brand_mismatch+{add}")

    if not landing_reg_domain and click_reg_domain in tracking:
        add = int(weights.get("unresolved_tracking_click_url", 5))
        score += add
        reasons.append(f"unresolved_tracking_click_url+{add}")

    feats["score"] = score
    feats["reasons"] = reasons
    return score, reasons, feats


def maybe_urlscan_submit(url: str, urlscan_cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not urlscan_cfg.get("enabled"):
        return None
    if requests is None:
        return {"error": "requests_not_installed"}
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        return {"error": "missing_URLSCAN_API_KEY_env"}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {
        "url": url,
        "visibility": urlscan_cfg.get("visibility", "public"),
        "tags": urlscan_cfg.get("tags", ["trading-scam-ad-watchdog"])
    }
    try:
        resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(payload), timeout=20)
        return resp.json() if resp.content else {"status_code": resp.status_code}
    except Exception as e:
        return {"error": f"urlscan_submit_failed: {e}"}


def urlscan_poll_result(uuid: str, urlscan_cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if requests is None:
        return {"error": "requests_not_installed"}
    if not uuid:
        return {"error": "missing_uuid"}

    api_key = os.environ.get("URLSCAN_API_KEY")
    headers = {}
    if api_key:
        headers["API-Key"] = api_key

    initial = float(urlscan_cfg.get("poll_initial_wait_s", 10))
    interval = float(urlscan_cfg.get("poll_interval_s", 2))
    timeout = float(urlscan_cfg.get("poll_timeout_s", 60))

    time.sleep(max(0.0, initial))
    start = time.time()
    url = f"https://urlscan.io/api/v1/result/{uuid}/"

    while (time.time() - start) < timeout:
        try:
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code == 200 and r.content:
                return r.json()
            if r.status_code in (404, 410):
                time.sleep(interval)
                continue
            return {"error": f"unexpected_status_{r.status_code}", "body": (r.text[:500] if r.text else None)}
        except Exception as e:
            return {"error": f"urlscan_poll_failed: {e}"}
    return {"error": "urlscan_poll_timeout"}


def flatten_creatives(extracted: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        for w in extracted.get("widgets", []):
            for c in w.get("creatives", []):
                out.append(c)
    except Exception:
        pass
    return out


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    preferred = ["run_id","target_id","page_url","creative_title","click_url","landing_url",
                 "click_reg_domain","landing_reg_domain","cluster_domain","risk_score","risk_level","risk_reasons"]
    cols = []
    seen = set()
    for c in preferred:
        if any(c in r for r in rows):
            cols.append(c); seen.add(c)
    for r in rows:
        for k in r.keys():
            if k not in seen:
                cols.append(k); seen.add(k)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def cluster_by_domain(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    clusters: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        dom = (r.get("cluster_domain") or "").lower()
        if not dom:
            continue
        c = clusters.setdefault(dom, {
            "cluster_domain": dom,
            "creative_count": 0,
            "targets": set(),
            "max_risk_score": 0,
            "sample_titles": [],
            "risk_level_counts": Counter(),
            "top_reasons": Counter(),
        })
        c["creative_count"] += 1
        c["targets"].add(r.get("target_id"))
        c["max_risk_score"] = max(int(c["max_risk_score"]), int(r.get("risk_score", 0)))
        if r.get("creative_title") and len(c["sample_titles"]) < 5:
            c["sample_titles"].append(r["creative_title"][:140])
        lvl = r.get("risk_level") or "none"
        c["risk_level_counts"][lvl] += 1
        for reason in (r.get("risk_reasons") or "").split(";"):
            reason = reason.strip()
            if reason:
                c["top_reasons"][reason] += 1

    out = []
    for dom, c in clusters.items():
        out.append({
            "cluster_domain": dom,
            "creative_count": c["creative_count"],
            "targets": sorted([t for t in c["targets"] if t]),
            "max_risk_score": c["max_risk_score"],
            "sample_titles": c["sample_titles"],
            "risk_level_counts": dict(c["risk_level_counts"]),
            "top_reasons": dict(c["top_reasons"].most_common(10))
        })
    out.sort(key=lambda x: (-int(x["max_risk_score"]), -int(x["creative_count"]), x["cluster_domain"]))
    return out


def risk_level(score: int, risk_cfg: Dict[str, Any]) -> str:
    hi = int(risk_cfg.get("high_risk_threshold", 30))
    med = int(risk_cfg.get("medium_risk_threshold", 15))
    if score >= hi:
        return "high"
    if score >= med:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def main() -> int:
    ap = argparse.ArgumentParser(description="Trading Scam Ad Watchdog collector (Playwright)")
    ap.add_argument("--config", default="config.sample.json", help="Path to JSON config")
    ap.add_argument("--out", default="out", help="Output directory for runs")
    ap.add_argument("--page-budget", type=int, default=None, help="Override run_profile.page_budget")
    ap.add_argument("--headless", action="store_true", help="Force headless")
    ap.add_argument("--headed", action="store_true", help="Force headed")
    ap.add_argument("--proxy", default=None, help="Proxy URL (e.g. http://user:pass@host:port)")
    ap.add_argument("--zip/--no-zip", dest="zip_output", default=None, action=argparse.BooleanOptionalAction)
    ap.add_argument("--urlscan/--no-urlscan", dest="urlscan_toggle", default=None, action=argparse.BooleanOptionalAction)
    ap.add_argument("--keep-query", action="store_true", help="Keep querystrings in stored URLs (NOT recommended)")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        save_json(cfg_path, DEFAULT_CONFIG)

    cfg = load_json(cfg_path)
    run_profile = cfg.get("run_profile", {})
    targets = cfg.get("targets", [])
    det = cfg.get("detection", {})
    urlscan_cfg = cfg.get("urlscan", {})
    risk_cfg = cfg.get("risk", {})

    if args.page_budget is not None:
        run_profile["page_budget"] = args.page_budget
    if args.headless:
        run_profile["headless"] = True
    if args.headed:
        run_profile["headless"] = False
    if args.zip_output is not None:
        run_profile["zip"] = bool(args.zip_output)
    if args.urlscan_toggle is not None:
        urlscan_cfg["enabled"] = bool(args.urlscan_toggle)

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    state_path = out_root / "state.json"
    state = read_state(state_path)

    run_id = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    run_dir = out_root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "run_id": run_id,
        "created_utc": utc_now_iso(),
        "config_path": str(cfg_path.resolve()),
        "run_profile": run_profile,
        "targets_total": len(targets),
        "tool": {"name": "trading-scam-ad-watchdog", "version": "v3.3.1"}
    }
    save_json(run_dir / "manifest.json", manifest)

    budget = int(run_profile.get("page_budget", 20))
    chosen, state = choose_targets_round_robin(targets, state, budget)

    summary_rows: List[Dict[str, Any]] = []
    creative_rows: List[Dict[str, Any]] = []

    max_urlscan = int(urlscan_cfg.get("max_submissions_per_run", 0)) if urlscan_cfg.get("enabled") else 0
    urlscan_used = 0

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=bool(run_profile.get("headless", True)))

        for idx, t in enumerate(chosen, start=1):
            target_id = t.get("id") or safe_slug(t.get("url", f"target_{idx}"))
            target_slug = safe_slug(target_id)
            tdir = run_dir / "targets" / target_slug
            tdir.mkdir(parents=True, exist_ok=True)

            har_path = tdir / "page.har"
            ctx_kwargs: Dict[str, Any] = {"record_har_path": str(har_path)}
            if args.proxy:
                ctx_kwargs["proxy"] = {"server": args.proxy}

            context = browser.new_context(**ctx_kwargs)
            page = context.new_page()

            req_log: List[Dict[str, Any]] = []
            resp_log: List[Dict[str, Any]] = []
            console_log: List[Dict[str, Any]] = []

            page.on("request", lambda req: req_log.append({"ts_utc": utc_now_iso(), "method": req.method, "url": redact_url(req.url, keep_query=args.keep_query), "resource_type": req.resource_type}))
            page.on("response", lambda resp: resp_log.append({"ts_utc": utc_now_iso(), "status": resp.status, "url": redact_url(resp.url, keep_query=args.keep_query), "from_service_worker": resp.from_service_worker}))
            page.on("console", lambda msg: console_log.append({"ts_utc": utc_now_iso(), "type": msg.type, "text": msg.text}))

            page_url = t.get("url")
            start = time.time()
            nav_ok = False
            nav_error = None
            main_redirect_chain: List[Dict[str, Any]] = []
            title = None
            html = ""

            try:
                resp = page.goto(page_url, wait_until="domcontentloaded", timeout=int(run_profile.get("timeout_ms", 45000)))
                nav_ok = True
                if resp is not None:
                    main_redirect_chain = build_redirect_chain(resp)
                if run_profile.get("auto_consent", True):
                    guess_cookie_consent(page)
                page.wait_for_timeout(int(run_profile.get("stabilize_ms", 7000)))
                title = page.title()
                html = page.content()
            except PwTimeoutError as e:
                nav_error = f"timeout: {e}"
            except Exception as e:
                nav_error = f"nav_error: {e}"

            elapsed_ms = int((time.time() - start) * 1000)

            try:
                page.screenshot(path=str(tdir / "viewport.png"), full_page=False)
            except Exception:
                pass
            try:
                page.screenshot(path=str(tdir / "full.png"), full_page=True)
            except Exception:
                pass
            try:
                (tdir / "page.html").write_text(html or "", encoding="utf-8")
            except Exception:
                pass

            container_css = det.get("taboola_container_css", DEFAULT_CONFIG["detection"]["taboola_container_css"])
            max_creatives = int(det.get("max_creatives_per_target", 30))
            try:
                extracted = extract_taboola_like(page, container_css, max_creatives)
            except Exception as e:
                extracted = {"error": str(e)}
            save_json(tdir / "taboola_extract.json", extracted)

            widget_shots: List[str] = []
            try:
                css_union = ", ".join(container_css)
                loc = page.locator(css_union)
                count = min(loc.count(), 3)
                for w in range(count):
                    outp = tdir / "widgets" / f"widget_{w+1:02d}.png"
                    outp.parent.mkdir(parents=True, exist_ok=True)
                    loc.nth(w).screenshot(path=str(outp))
                    widget_shots.append(str(outp.relative_to(run_dir)))
            except Exception:
                pass

            license_re = det.get("license_keyword_regex", DEFAULT_CONFIG["detection"]["license_keyword_regex"])
            hits = keyword_hits(html or "", license_re)
            creative_titles: List[str] = []
            try:
                for w in extracted.get("widgets", []):
                    for c in w.get("creatives", []):
                        if c.get("title"):
                            creative_titles.append(c["title"])
                hits += keyword_hits("\\n".join(creative_titles), license_re)
                hits = sorted(set(hits))
            except Exception:
                pass
            save_json(tdir / "license_hits.json", {"regex": license_re, "hits": hits})

            urlscan_map: Dict[str, Dict[str, Any]] = {}
            if urlscan_cfg.get("enabled") and urlscan_used < max_urlscan:
                creatives = flatten_creatives(extracted if isinstance(extracted, dict) else {})
                for c in creatives:
                    if urlscan_used >= max_urlscan:
                        break
                    href = c.get("href")
                    if not href:
                        continue
                    submit = maybe_urlscan_submit(href, urlscan_cfg)
                    uuid = (submit or {}).get("uuid") if isinstance(submit, dict) else None
                    polled = None
                    if uuid and urlscan_cfg.get("poll_for_result"):
                        polled = urlscan_poll_result(uuid, urlscan_cfg)
                    urlscan_map[href] = {"submit": submit, "polled": polled}
                    urlscan_used += 1
                    time.sleep(1.0)
                save_json(tdir / "urlscan_map.json", urlscan_map)

            save_json(tdir / "requests.json", req_log)
            save_json(tdir / "responses.json", resp_log)
            save_json(tdir / "console.json", console_log)
            save_json(tdir / "redirect_chain.json", main_redirect_chain)

            meta = {
                "target": t,
                "nav_ok": nav_ok,
                "nav_error": nav_error,
                "elapsed_ms": elapsed_ms,
                "title": title,
                "taboola_detected": bool(extracted.get("hasTaboolaSignal")) if isinstance(extracted, dict) else False,
                "taboola_widget_count": extracted.get("widgetCount") if isinstance(extracted, dict) else None,
                "widget_screenshots": widget_shots,
                "license_hits": hits,
                "captured": {
                    "har": str(har_path.relative_to(run_dir)),
                    "viewport": str((tdir / "viewport.png").relative_to(run_dir)),
                    "full": str((tdir / "full.png").relative_to(run_dir)),
                    "html": str((tdir / "page.html").relative_to(run_dir)),
                }
            }
            save_json(tdir / "meta.json", meta)

            extracted_creatives = flatten_creatives(extracted if isinstance(extracted, dict) else {})
            high_count = 0
            max_score_target = 0

            for c in extracted_creatives:
                click_url = c.get("href") or ""
                click_host = get_host(click_url)
                click_reg = get_registrable_domain(click_host)

                landing_url = ""
                landing_reg = ""
                if click_url in urlscan_map:
                    polled = urlscan_map[click_url].get("polled") if isinstance(urlscan_map[click_url], dict) else None
                    if isinstance(polled, dict):
                        landing_url = (polled.get("page") or {}).get("url") or ""
                        if not landing_url:
                            landing_url = (polled.get("task") or {}).get("url") or ""
                        landing_reg = get_registrable_domain(get_host(landing_url))
                    if not landing_url:
                        sub = urlscan_map[click_url].get("submit")
                        if isinstance(sub, dict):
                            landing_url = sub.get("result") or sub.get("api") or ""

                score, reasons, feats = compute_risk(
                    title=c.get("title") or "",
                    click_reg_domain=click_reg,
                    landing_reg_domain=landing_reg,
                    license_hits=hits,
                    risk_cfg=risk_cfg
                )
                lvl = risk_level(score, risk_cfg)
                max_score_target = max(max_score_target, score)
                if lvl == "high":
                    high_count += 1

                cluster_dom = landing_reg or click_reg

                creative_rows.append({
                    "run_id": run_id,
                    "target_id": target_id,
                    "page_url": page_url,
                    "creative_title": (c.get("title") or ""),
                    "click_url": redact_url(click_url, keep_query=args.keep_query),
                    "landing_url": redact_url(landing_url, keep_query=args.keep_query) if landing_url else "",
                    "img_url": redact_url(c.get("img") or "", keep_query=args.keep_query) if c.get("img") else "",
                    "click_reg_domain": click_reg,
                    "landing_reg_domain": landing_reg,
                    "cluster_domain": cluster_dom,
                    "risk_score": score,
                    "risk_level": lvl,
                    "risk_reasons": ";".join(reasons),
                    "brand_tokens": ",".join(feats.get("brand_tokens", []) or []),
                    "keyword_hit_count": feats.get("keyword_hit_count", 0),
                })

            summary_rows.append({
                "run_id": run_id,
                "target_id": target_id,
                "url": page_url,
                "nav_ok": nav_ok,
                "elapsed_ms": elapsed_ms,
                "taboola_detected": meta["taboola_detected"],
                "widget_count": meta["taboola_widget_count"],
                "license_hits": ";".join(hits),
                "high_risk_creatives": high_count,
                "max_risk_score": max_score_target
            })

            try:
                context.close()
            except Exception:
                pass

            jitter_sleep(int(run_profile.get("min_delay_ms", 5000)), int(run_profile.get("max_delay_ms", 15000)))

        try:
            browser.close()
        except Exception:
            pass

    save_json(run_dir / "summary.json", summary_rows)
    if summary_rows:
        with (run_dir / "summary.csv").open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
            w.writeheader()
            for r in summary_rows:
                w.writerow(r)

    write_jsonl(run_dir / "creatives_flat.jsonl", creative_rows)
    write_csv(run_dir / "creatives_flat.csv", creative_rows)

    clusters = cluster_by_domain(creative_rows)
    save_json(run_dir / "landing_clusters.json", clusters)
    write_csv(run_dir / "landing_clusters.csv", clusters)

    risk_counts = Counter([r.get("risk_level") or "none" for r in creative_rows])
    top_domains = []
    for c in clusters[:20]:
        top_domains.append({
            "cluster_domain": c["cluster_domain"],
            "creative_count": c["creative_count"],
            "max_risk_score": c["max_risk_score"],
            "risk_level_counts": c["risk_level_counts"],
            "top_reasons": c["top_reasons"]
        })
    risk_report = {
        "run_id": run_id,
        "created_utc": utc_now_iso(),
        "urlscan_enabled": bool(urlscan_cfg.get("enabled")),
        "urlscan_used": urlscan_used,
        "creative_total": len(creative_rows),
        "risk_level_counts": dict(risk_counts),
        "top_domains": top_domains
    }
    save_json(run_dir / "risk_report.json", risk_report)

    state["last_run_utc"] = utc_now_iso()
    save_json(state_path, state)

    if run_profile.get("zip", True):
        zip_path = out_root / "runs" / f"{run_id}.zip"
        zip_dir(run_dir, zip_path)

    print(json.dumps({
        "run_id": run_id,
        "out_dir": str(run_dir.resolve()),
        "zipped": bool(run_profile.get("zip", True)),
        "targets_crawled": len(chosen),
        "urlscan_enabled": bool(urlscan_cfg.get("enabled")),
        "urlscan_used": urlscan_used,
        "creatives_total": len(creative_rows),
        "clusters_total": len(clusters)
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
