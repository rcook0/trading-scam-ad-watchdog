#!/usr/bin/env python3
"""
MSN/Taboola Watchdog — v3.3 seed collector (single file)

- Visits budgeted MSN pages
- Captures evidence: screenshots, HTML, HAR, network logs, redirect chain, extracted "Taboola-ish" creatives
- Optionally submits click URLs to urlscan.io (OFF by default)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import re
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

from playwright.sync_api import sync_playwright, TimeoutError as PwTimeoutError  # type: ignore

DEFAULT_CONFIG = {
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
        "tags": ["msn-taboola-watchdog"],
        "max_submissions_per_run": 10
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

def maybe_urlscan_submit(url: str, out_dir: Path, urlscan_cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not urlscan_cfg.get("enabled"):
        return None
    if requests is None:
        return {"error": "requests_not_installed"}
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        return {"error": "missing_URLSCAN_API_KEY_env"}
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": urlscan_cfg.get("visibility", "public"), "tags": urlscan_cfg.get("tags", ["msn-taboola-watchdog"])}
    try:
        resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(payload), timeout=20)
        data = resp.json() if resp.content else {"status_code": resp.status_code}
        save_json(out_dir / "urlscan_submit.json", data)
        return data
    except Exception as e:
        return {"error": f"urlscan_submit_failed: {e}"}

def main() -> int:
    ap = argparse.ArgumentParser(description="MSN/Taboola Watchdog collector (Playwright)")
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
        "tool": {"name": "msn-taboola-watchdog", "version": "v3.3-seed"}
    }
    save_json(run_dir / "manifest.json", manifest)

    budget = int(run_profile.get("page_budget", 20))
    chosen, state = choose_targets_round_robin(targets, state, budget)

    summary_rows: List[Dict[str, Any]] = []

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

            url = t.get("url")
            start = time.time()
            nav_ok = False
            nav_error = None
            main_redirect_chain: List[Dict[str, Any]] = []
            title = None
            html = ""

            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=int(run_profile.get("timeout_ms", 45000)))
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

            if urlscan_cfg.get("enabled") and urlscan_used < max_urlscan:
                creatives = []
                try:
                    for w in extracted.get("widgets", []):
                        creatives.extend(w.get("creatives", []))
                except Exception:
                    creatives = []
                urlscan_results: List[Dict[str, Any]] = []
                for c in creatives:
                    if urlscan_used >= max_urlscan:
                        break
                    href = c.get("href")
                    if not href:
                        continue
                    cdir = tdir / "urlscan" / f"creative_{urlscan_used+1:02d}"
                    cdir.mkdir(parents=True, exist_ok=True)
                    res = maybe_urlscan_submit(href, cdir, urlscan_cfg)
                    urlscan_results.append({"href": redact_url(href, keep_query=args.keep_query), "result": res})
                    urlscan_used += 1
                    time.sleep(1.0)
                save_json(tdir / "urlscan_results.json", urlscan_results)

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

            summary_rows.append({
                "run_id": run_id,
                "target_id": target_id,
                "url": url,
                "nav_ok": nav_ok,
                "elapsed_ms": elapsed_ms,
                "taboola_detected": meta["taboola_detected"],
                "widget_count": meta["taboola_widget_count"],
                "license_hits": ";".join(hits),
            })

            try:
                context.close()  # flush HAR
            except Exception:
                pass

            jitter_sleep(int(run_profile.get("min_delay_ms", 5000)), int(run_profile.get("max_delay_ms", 15000)))

        try:
            browser.close()
        except Exception:
            pass

    save_json(run_dir / "summary.json", summary_rows)

    csv_path = run_dir / "summary.csv"
    if summary_rows:
        cols = list(summary_rows[0].keys())
        lines = [",".join(cols)]
        for r in summary_rows:
            lines.append(",".join('"' + str(r.get(c, "")).replace('"', '""') + '"' for c in cols))
        csv_path.write_text("\\n".join(lines), encoding="utf-8")

    state["last_run_utc"] = utc_now_iso()
    save_json(out_root / "state.json", state)

    if run_profile.get("zip", True):
        zip_path = out_root / "runs" / f"{run_id}.zip"
        zip_dir(run_dir, zip_path)

    print(json.dumps({
        "run_id": run_id,
        "out_dir": str(run_dir.resolve()),
        "zipped": bool(run_profile.get("zip", True)),
        "targets_crawled": len(chosen),
        "urlscan_enabled": bool(urlscan_cfg.get("enabled")),
        "urlscan_used": urlscan_used
    }, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
