"""
NORTHWATCH cli

  nw doctor    validate every feed, print a health table
  nw resolve   YouTube @handles -> channel IDs -> sources.lock.yaml
  nw build     run the pipeline, write web/data/feed.json
  nw notify    push exploited-now items to ntfy
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

from .pipeline import (Item, cluster, enrich, fetch_all, heat, kind, load_kev,
                       load_sources, severity)
from .summarize import resolve_chain, summarize_cluster

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "config" / "sources.yaml"
LOCK = ROOT / "config" / "sources.lock.yaml"
OUT = ROOT / "web" / "data"
UTC = timezone.utc

# Which clusters are worth a model call. Everything else renders with its
# headline, source attribution and metadata — which for most stories is enough.
# On a free tier this is the difference between finishing the run and hitting 429.
#
# Recalibrated alongside heat()'s 72h half-life: the gentler decay raises heat
# scores across the board, so the old 18.0 (tuned for a 12h half-life) let every
# story in a 5-day window clear the bar. 26.0 restores roughly the old ~45-50
# briefs/run selectivity instead of briefing all 70.
BRIEF_MIN_HEAT = 26.0


def _merge_lock(sources: list[dict]) -> None:
    if not LOCK.exists():
        return
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8")) or {}
    for s in sources:
        if s["id"] in lock:
            s.update(lock[s["id"]])


# --------------------------------------------------------------------------

def cmd_doctor(_args) -> int:
    defaults, sources = load_sources(SOURCES)
    _merge_lock(sources)
    ua = {"User-Agent": defaults["user_agent"]}

    def probe(src):
        if not src.get("url"):
            return src, "UNRESOLVED", 0, "run `nw resolve`"
        try:
            r = requests.get(src["url"], headers=ua, timeout=20)
            if r.status_code != 200:
                return src, "DEAD", 0, f"HTTP {r.status_code}"
            import feedparser
            n = len(feedparser.parse(r.content).entries)
            return (src, "OK", n, "") if n else (src, "EMPTY", 0, "0 entries")
        except Exception as exc:                                # noqa: BLE001
            return src, "DEAD", 0, type(exc).__name__

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(probe, sources))

    print(f"\n  {'SOURCE':<22}{'TIER':<11}{'GATE':<7}{'STATUS':<11}{'ITEMS':<7}NOTE")
    print("  " + "-" * 74)
    bad = 0
    for src, status, n, note in sorted(results, key=lambda r: (r[1] != "OK", r[0]["tier"])):
        bad += status != "OK"
        col = {"OK": "\033[32m", "EMPTY": "\033[33m"}.get(status, "\033[31m")
        gate = "yes" if src.get("gate") else "-"
        print(f"  {src['id']:<22}{src['tier']:<11}{gate:<7}{col}{status:<11}\033[0m{n or '':<7}{note}")

    print(f"\n  {len(results)-bad}/{len(results)} healthy.")
    if bad:
        print("  Fix or delete anything DEAD before you trust the feed.\n")
    return 1 if bad else 0


CHANNEL_RE = re.compile(r'"(?:channelId|externalId)":"(UC[\w-]{22})"')


def cmd_resolve(_args) -> int:
    _, sources = load_sources(SOURCES)
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8")) if LOCK.exists() else {}
    ua = {"User-Agent": "Mozilla/5.0 (compatible; northwatch/2.0)"}

    for src in sources:
        if src["tier"] != "video" or src["id"] in lock:
            continue
        try:
            r = requests.get(f"https://www.youtube.com/{src['handle']}", headers=ua, timeout=20)
            m = CHANNEL_RE.search(r.text)
            if not m:
                print(f"  [miss] {src['handle']}")
                continue
            lock[src["id"]] = {
                "url": f"https://www.youtube.com/feeds/videos.xml?channel_id={m.group(1)}",
                "site": "youtube.com",
            }
            print(f"  [ok]   {src['handle']:<22} {m.group(1)}")
        except Exception as exc:                                # noqa: BLE001
            print(f"  [fail] {src['handle']} — {exc}")

    LOCK.write_text(yaml.safe_dump(lock, sort_keys=True), encoding="utf-8")
    print(f"\n  wrote {LOCK.name} — commit it.")
    return 0


# --------------------------------------------------------------------------

def cmd_build(args) -> int:
    print("\nbackend")
    chain = resolve_chain(args.backend)
    if args.backend not in ("none",) and not chain:
        return 1

    defaults, sources = load_sources(SOURCES)
    _merge_lock(sources)
    if args.threshold is not None:
        defaults["relevance_threshold"] = args.threshold

    print("\nfetch")
    items = fetch_all(sources, defaults, max_age_hours=args.window)
    if not items:
        print("No items. Run `nw doctor`.")
        return 1

    print(f"\nenrich  ({len(items)} items)")
    items = enrich(items, load_kev())

    print("\ncluster")
    groups = sorted(cluster(items), key=heat, reverse=True)[: args.limit]
    print(f"  {len(items)} items -> {len(groups)} stories")

    briefed = sum(1 for g in groups if heat(g) >= BRIEF_MIN_HEAT)
    print(f"\nbrief   ({briefed} of {len(groups)} above heat {BRIEF_MIN_HEAT}; rest render bare)")

    stories = []
    for n, cl in enumerate(groups, 1):
        h = heat(cl)
        lead = max(cl, key=lambda x: (bool(x.image), x.weight, x.published))
        brief = (summarize_cluster([i.dict() for i in cl], chain)
                 if h >= BRIEF_MIN_HEAT
                 else {"abstract": "", "why": "", "action": "", "confidence": "low"})

        stories.append({
            "id": lead.uid,
            "title": lead.title,
            "link": lead.link,
            "kind": kind(cl),                     # security | tech -> which card
            "tier": lead.tier,
            "image": lead.image,
            "published": max(i.published for i in cl).isoformat(),
            "severity": severity(cl),
            "heat": h,
            "canada": any(i.canada for i in cl),
            "cves": sorted({c for i in cl for c in i.cves}),
            "kev": sorted({c for i in cl for c in i.kev}),
            "epss": round(max(i.max_epss for i in cl), 3),
            "vendors": sorted({v for i in cl for v in i.vendors})[:4],
            "sources": [{"name": i.source_name, "site": i.site, "link": i.link}
                        for i in sorted(cl, key=lambda x: -x.weight)],
            **brief,
        })
        if briefed and n <= briefed and n % 10 == 0:
            print(f"  {n}/{briefed}")

    OUT.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": datetime.now(UTC).isoformat(),
        "counts": _counts(stories),
        "sources": [{"id": s["id"], "name": s["name"], "site": s.get("site", ""),
                     "tier": s["tier"]} for s in sources if s.get("url")],
        "stories": stories,
    }
    # `excerpt` is deliberately absent. Publisher prose does not leave this process.
    (OUT / "feed.json").write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")
    c = payload["counts"]
    print(f"\n  wrote web/data/feed.json — {c['total']} stories "
          f"({c['security']} security, {c['tech']} tech, {c['kev']} exploited)\n")
    return 0


def _counts(stories: list[dict]) -> dict:
    c = {"total": len(stories), "critical": 0, "high": 0, "medium": 0, "info": 0,
         "canada": 0, "kev": 0, "security": 0, "tech": 0}
    for s in stories:
        c[s["severity"]] += 1
        c[s["kind"]] += 1
        c["canada"] += bool(s["canada"])
        c["kev"] += bool(s["kev"])
    return c


def cmd_notify(_args) -> int:
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        print("NTFY_TOPIC not set.")
        return 1
    feed = json.loads((OUT / "feed.json").read_text(encoding="utf-8"))
    hot = [s for s in feed["stories"] if s["kev"]][:5]
    if not hot:
        print("Nothing actively exploited. Staying quiet.")
        return 0
    for s in hot:
        requests.post(
            f"https://ntfy.sh/{topic}",
            data=(s.get("action") or s.get("abstract") or s["title"]).encode(),
            headers={"Title": f"[{','.join(s['kev'][:2])}] {s['title'][:70]}",
                     "Priority": "high", "Tags": "rotating_light", "Click": s["link"]},
            timeout=15,
        )
    print(f"  pushed {len(hot)}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="nw")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor").set_defaults(fn=cmd_doctor)
    sub.add_parser("resolve").set_defaults(fn=cmd_resolve)
    sub.add_parser("notify").set_defaults(fn=cmd_notify)

    b = sub.add_parser("build")
    b.add_argument("--window", type=int, default=120)
    b.add_argument("--limit", type=int, default=70)
    b.add_argument("--threshold", type=int, default=None,
                   help="override cyber-relevance gate (default 3)")
    b.add_argument("--backend",
                   choices=["auto", "none", "gemini", "groq", "cloudflare", "ollama"],
                   default="auto")
    b.set_defaults(fn=cmd_build)

    a = p.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
