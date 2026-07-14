"""
NORTHWATCH pipeline: fetch -> gate -> enrich -> cluster -> score.

What changed in v2, and why:

  The v1 build was a threat-intel console. It ranked a Cyber Centre advisory above
  a global platform breach, because Canada carried a scoring bonus and "advisory"
  carried the highest weight. That is the correct design for a SOC watch floor and
  the wrong design for the thing this actually is: a way to stop reading forty
  articles a day.

  So: Canada is now a filter, not a bonus. Tech news is in. And a general-interest
  feed has to earn its way in through the relevance gate below.

Standing rule, unchanged:
  Publisher-sanctioned RSS only. We keep title, link, and a short excerpt used
  solely as model input. Article bodies are never persisted and never served.
"""
from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Iterable

import feedparser
import requests
import yaml

UTC = timezone.utc
EXCERPT_CHARS = 900


@dataclass
class Item:
    uid: str
    title: str
    link: str
    source_id: str
    source_name: str
    site: str
    tier: str                      # security | tech | advisory | research | video
    published: datetime
    excerpt: str = ""              # model input only. never rendered, never stored.
    image: str | None = None
    weight: float = 1.0
    canada: bool = False

    cves: list[str] = field(default_factory=list)
    kev: list[str] = field(default_factory=list)
    max_epss: float = 0.0
    iocs: dict[str, list[str]] = field(default_factory=dict)
    vendors: list[str] = field(default_factory=list)
    exploited: bool = False
    incident: bool = False
    relevance: int = 0             # cyber-relevance, 0..99

    def dict(self):
        d = asdict(self)
        d["published"] = self.published.isoformat()
        return d


# ===========================================================================
# THE GATE
#
# The Verge posts ~40 items a day. Three of them matter to you. Without this,
# the feed is phone reviews and the security signal drowns.
#
# Scoring: 3 points per distinct hard-security term, 2 per privacy/regulatory
# term, 1 per adjacent term. A CVE is an automatic pass. Commerce language in
# the TITLE is an automatic reject, unless a hard-security term also fires —
# so "Chrome zero-day patched" survives, "best password managers of 2026" does
# not, and that second one is affiliate bait wearing a security costume.
# ===========================================================================

_HARD = [
    "breach", "breached", "hacked", "hacker", "hacking", "ransomware", "malware",
    "vulnerabilit", "zero-day", "0-day", "phish", "spyware", "backdoor", "botnet",
    "data leak", "leaked data", "cyberattack", "cyber attack", "infostealer",
    "stalkerware", "patch tuesday", "security flaw", "security bug", "compromis",
    "exploit", "exfiltrat", "outage", "takedown", "arrested", "indicted",
    # A government weakening encryption is a security story, full stop. These sat
    # in the soft list at first and the gate dropped Apple pulling encrypted iCloud
    # backups in the UK — precisely the kind of story this site exists to surface.
    "encrypt", "end-to-end", "surveillance", "wiretap", "lawful access",
]
_SOFT = [
    "privacy", "authenticat", "password",
    "passkey", "two-factor", r"\b2FA\b", r"\bMFA\b", r"\bVPN\b", "tracking", "tracker",
    "GDPR", "PIPEDA", "data protection", "bug bounty", "disclosure", "DDoS",
    "deepfake", "scam", "fraud", "identity theft", "dark web", "zero trust",
    "firewall", "antivirus", r"\bEDR\b", "SIEM", "CISO", "infosec", "data collection",
    "hacking forum", "leak",
]
_ADJACENT = [
    "prompt injection", "jailbreak", "model weights", "open weights", "AI safety",
    "guardrail", "secure boot", "firmware", "kernel", "sandbox", "permission",
    "antitrust", "regulat", r"\bban\b", "lawsuit", "court", "subpoena", "warrant",
    r"\bFTC\b", r"\bFCC\b", "EU Commission", "watchdog", "age verification",
    "content moderation", "probe", "investigation", "sued", "whistleblower",
]
# Shopping and review content. Never news.
_COMMERCE = [
    r"\breview\b", r"\bdeal\b", r"\bdeals\b", r"\bbest\b", r"\bvs\.?\b", "hands-on",
    "unboxing", r"\bsale\b", "discount", "coupon", "prime day", "black friday",
    "gift guide", "how to watch", "where to buy", "cheapest", "price drop",
    r"\bwe tried\b", r"\brank(?:ed|ing)\b", r"\btop \d+\b", "buying guide",
    "preorder", "which should you buy", r"\bdiscounted\b",
]

_rx = lambda terms: re.compile("|".join(terms), re.I)
HARD_RE, SOFT_RE, ADJ_RE, COMMERCE_RE = _rx(_HARD), _rx(_SOFT), _rx(_ADJACENT), _rx(_COMMERCE)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def relevance(title: str, excerpt: str = "") -> int:
    """0 = irrelevant. 99 = carries a CVE. Threshold lives in sources.yaml."""
    blob = f"{title} {excerpt}"
    if CVE_RE.search(blob):
        return 99
    hard = {m.lower() for m in HARD_RE.findall(blob)}
    if COMMERCE_RE.search(title) and not hard:
        return 0
    return (3 * len(hard)
            + 2 * len({m.lower() for m in SOFT_RE.findall(blob)})
            + 1 * len({m.lower() for m in ADJ_RE.findall(blob)}))


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")
_clean = lambda h: WS_RE.sub(" ", TAG_RE.sub(" ", h or "")).strip()


def _parse_date(entry) -> datetime:
    for k in ("published_parsed", "updated_parsed"):
        if entry.get(k):
            return datetime.fromtimestamp(time.mktime(entry[k]), tz=UTC)
    return datetime.now(UTC)


def _image_of(entry) -> str | None:
    # media:thumbnail is always an image. media:content is not — YouTube's feed
    # sets it to the legacy Flash embed URL (type application/x-shockwave-flash),
    # which would otherwise be picked up ahead of the real hqdefault.jpg thumbnail.
    for th in entry.get("media_thumbnail", []) or []:
        if th.get("url"):
            return th["url"]
    for mc in entry.get("media_content", []) or []:
        if mc.get("url") and str(mc.get("type", "")).startswith("image"):
            return mc["url"]
    for enc in entry.get("enclosures", []) or []:
        if str(enc.get("type", "")).startswith("image"):
            return enc.get("href")
    m = re.search(r'<img[^>]+src="([^"]+)"', entry.get("summary", "") or "")
    return m.group(1) if m else None


def load_sources(path: str) -> tuple[dict, list[dict]]:
    cfg = yaml.safe_load(open(path, encoding="utf-8"))
    defaults = cfg.pop("defaults", {})
    flat = []
    for tier, entries in cfg.items():
        for e in entries or []:
            e["tier"] = tier
            flat.append(e)
    return defaults, flat


def fetch_source(src: dict, defaults: dict) -> tuple[list[Item], int]:
    """Returns (admitted items, count dropped by the gate)."""
    url = src.get("url")
    if not url:
        return [], 0

    try:
        raw = requests.get(url, headers={"User-Agent": defaults["user_agent"]},
                           timeout=defaults.get("timeout", 20))
        raw.raise_for_status()
    except Exception as exc:                                    # noqa: BLE001
        print(f"  [dead] {src['id']:<20} {type(exc).__name__}")
        return [], 0

    parsed = feedparser.parse(raw.content)
    gated = bool(src.get("gate"))
    floor = defaults.get("relevance_threshold", 3)
    out, dropped = [], 0

    for entry in parsed.entries[:defaults.get("max_items_per_feed", 40)]:
        link, title = entry.get("link") or "", _clean(entry.get("title", ""))
        if not link or not title:
            continue

        body = _clean(entry.get("summary", "") or entry.get("description", ""))
        for c in entry.get("content", []) or []:
            body = body or _clean(c.get("value", ""))

        rel = relevance(title, body[:400])
        if gated and rel < floor:
            dropped += 1
            continue

        out.append(Item(
            uid=hashlib.sha1(link.encode()).hexdigest()[:16],
            title=title, link=link,
            source_id=src["id"], source_name=src["name"], site=src.get("site", ""),
            tier=src["tier"], published=_parse_date(entry),
            excerpt=body[:EXCERPT_CHARS], image=_image_of(entry),
            weight=float(src.get("weight", 1.0)), canada=bool(src.get("canada")),
            relevance=rel,
        ))

    tail = f"  ({dropped} gated out)" if dropped else ""
    print(f"  [ok]   {src['id']:<20} {len(out):>3} items{tail}")
    return out, dropped


def fetch_all(sources: list[dict], defaults: dict, max_age_hours: int = 48) -> list[Item]:
    cutoff = datetime.now(UTC) - timedelta(hours=max_age_hours)
    items, seen, total_dropped = [], set(), 0
    for src in sources:
        got, dropped = fetch_source(src, defaults)
        total_dropped += dropped
        for it in got:
            if it.published >= cutoff and it.uid not in seen:
                seen.add(it.uid)
                items.append(it)
    if total_dropped:
        print(f"\n  gate rejected {total_dropped} items as non-security noise")
    return items


# ---------------------------------------------------------------------------
# Enrich
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
DEFANGED_RE = re.compile(r"\b(?:[\w-]+\[\.\])+[a-z]{2,}\b", re.I)

EXPLOIT_RE = re.compile(
    r"\b(actively exploited|exploited in the wild|zero-day|0-day|under attack|"
    r"in-the-wild|being exploited|weaponi[sz]ed|emergency patch|out-of-band patch)\b", re.I)
INCIDENT_RE = re.compile(
    r"\b(ransomware|data breach|breached|compromised|intrusion|extortion|"
    r"stolen data|leaked data|hacked|cyberattack|cyber attack|threat actor|APT\d+|"
    r"claimed responsibility|dark web leak)\b", re.I)
CANADA_RE = re.compile(
    r"\b(Canada|Canadian|Ontario|Quebec|Toronto|Ottawa|Vancouver|Montreal|Alberta|"
    r"Cyber Centre|CCCS|RCMP|OSFI|PIPEDA|Privacy Commissioner of Canada)\b")
VENDOR_RE = re.compile(
    r"\b(Microsoft|Windows|Azure|Entra|Exchange|Fortinet|Cisco|Ivanti|Citrix|VMware|"
    r"Palo Alto|SonicWall|Atlassian|Apache|Oracle|SAP|Chrome|Firefox|Linux|Kubernetes|"
    r"GitLab|GitHub|Okta|Splunk|Adobe|Apple|Android|Google|Meta|Amazon|AWS|Cloudflare|"
    r"OpenAI|Anthropic|Signal|WhatsApp|Telegram|Veeam|MOVEit|SolarWinds|CrowdStrike)\b", re.I)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def load_kev() -> set[str]:
    """CISA KEV. If a CVE is in here, it is being used against real targets today."""
    try:
        r = requests.get(KEV_URL, timeout=30)
        r.raise_for_status()
        kev = {v["cveID"].upper() for v in r.json().get("vulnerabilities", [])}
        print(f"  KEV: {len(kev)} CVEs")
        return kev
    except Exception as exc:                                    # noqa: BLE001
        print(f"  KEV unavailable ({exc}) — continuing without it")
        return set()


def load_epss(cves: Iterable[str]) -> dict[str, float]:
    """EPSS: probability of exploitation in the next 30 days. Free, no key."""
    cves, scores = sorted(set(cves)), {}
    for i in range(0, len(cves), 100):
        try:
            r = requests.get(EPSS_URL, params={"cve": ",".join(cves[i:i + 100])}, timeout=30)
            r.raise_for_status()
            for row in r.json().get("data", []):
                scores[row["cve"].upper()] = float(row.get("epss", 0))
        except Exception:                                       # noqa: BLE001
            pass
    return scores


def enrich(items: list[Item], kev: set[str]) -> list[Item]:
    for it in items:
        blob = f"{it.title} {it.excerpt}"
        it.cves = sorted({c.upper() for c in CVE_RE.findall(blob)})
        it.kev = [c for c in it.cves if c in kev]
        it.vendors = sorted({v.title() for v in VENDOR_RE.findall(blob)})[:4]
        it.exploited = bool(it.kev) or bool(EXPLOIT_RE.search(blob))
        it.incident = bool(INCIDENT_RE.search(blob))
        if not it.canada:
            it.canada = bool(CANADA_RE.search(blob))
        iocs = {
            "ipv4": sorted(set(IPV4_RE.findall(blob)))[:8],
            "sha256": sorted(set(SHA256_RE.findall(blob)))[:8],
            "domains": sorted(set(DEFANGED_RE.findall(blob)))[:8],
        }
        it.iocs = {k: v for k, v in iocs.items() if v}

    all_cves = {c for it in items for c in it.cves}
    if all_cves:
        epss = load_epss(all_cves)
        for it in items:
            it.max_epss = max((epss.get(c, 0.0) for c in it.cves), default=0.0)
    return items


# ---------------------------------------------------------------------------
# Cluster
# ---------------------------------------------------------------------------

STOP = {"the", "a", "an", "of", "in", "on", "to", "for", "and", "or", "is", "are",
        "with", "by", "as", "at", "from", "new", "after", "over", "into", "its",
        "that", "this", "has", "have", "was", "were", "be", "it", "us", "says",
        "attack", "attacks", "security", "cyber", "hackers", "flaw", "bug"}


def _tokens(t: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]{3,}", t.lower()) if w not in STOP}


def build_idf(items: list[Item]) -> dict[str, float]:
    """Rare words identify a story; common words don't. 'Apple' appears in forty
    items today and tells you nothing. 'iCloud' appears in two and tells you
    everything. Inverse document frequency is how you encode that."""
    df: dict[str, int] = {}
    for it in items:
        for t in _tokens(f"{it.title} {it.excerpt[:300]}"):
            df[t] = df.get(t, 0) + 1
    n = len(items) or 1
    return {t: math.log(1 + n / c) for t, c in df.items()}


def _vec(it: Item, idf: dict[str, float]) -> dict[str, float]:
    title_toks = _tokens(it.title)
    all_toks = _tokens(f"{it.title} {it.excerpt[:300]}")
    # Headline tokens count double. The headline is the strongest statement of
    # what a story is about; the body wanders.
    return {t: idf.get(t, 1.0) * (2.0 if t in title_toks else 1.0) for t in all_toks}


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    common = set(a) & set(b)
    if not common:
        return 0.0
    num = sum(a[t] * b[t] for t in common)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return num / (na * nb) if na and nb else 0.0


def cluster(items: list[Item], threshold: float = 0.30) -> list[list[Item]]:
    """Two passes at 'is this the same story':

      1. Shared CVE -> same story, no argument. Exact, and it's the structural
         advantage security news has over general news.
      2. Otherwise, IDF-weighted cosine over title + excerpt.

    Plain title-overlap (Jaccard) was the first attempt and it failed on exactly
    the case that matters most: two outlets covering one tech story in different
    words. "Apple pulls encrypted backups in the UK" and "Apple withdraws
    encrypted backups in Britain" share three words out of thirteen. Jaccard said
    0.23 and split them. IDF sees that 'encrypted' and 'backups' are rare today
    and merges them, which is the whole point of the site.
    """
    items = sorted(items, key=lambda i: i.published, reverse=True)
    idf = build_idf(items)
    vecs = {it.uid: _vec(it, idf) for it in items}

    clusters: list[list[Item]] = []
    for it in items:
        for cl in clusters:
            for member in cl[:3]:
                if it.cves and member.cves and set(it.cves) & set(member.cves):
                    cl.append(it)
                    break
                if _cosine(vecs[it.uid], vecs[member.uid]) >= threshold:
                    cl.append(it)
                    break
            else:
                continue
            break
        else:
            clusters.append([it])
    return clusters


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

def severity(cl: list[Item]) -> str:
    if any(i.kev for i in cl):
        return "critical"
    if any(i.exploited for i in cl) or max(i.max_epss for i in cl) >= 0.5:
        return "high"
    if any(i.cves for i in cl) or any(i.incident for i in cl) \
            or any(i.tier == "advisory" for i in cl):
        return "medium"
    return "info"


def kind(cl: list[Item]) -> str:
    """Which card the frontend draws. Security stories get the triage strip.
    Tech stories get a headline and a picture, because that's what they are."""
    if any(i.tier in ("security", "advisory", "research") for i in cl):
        return "security"
    return "tech"


SEV_BOOST = {"critical": 45.0, "high": 24.0, "medium": 8.0, "info": 0.0}


def heat(cl: list[Item]) -> float:
    """Corroboration first. Five outlets covering one story is the single
    strongest signal that it matters — that's true for news generally, and it's
    the thing peek.vn gets right.

    72h half-life, matched to the 5-day retention window and once-daily refresh.
    The original 12h half-life was tuned for a 3-hourly refresh over a 48h window;
    left in place after both were widened, it crushed anything past ~a day to
    near-zero heat regardless of severity — a KEV-listed, EPSS-0.947 advisory
    landed at #69 of 70 for being 3 days old. Criticality and impact should still
    be able to win a spot near the top within the window's shelf life.
    """
    now = datetime.now(UTC)
    age_h = max((now - max(i.published for i in cl)).total_seconds() / 3600, 0.0)

    corroboration = math.log1p(len({i.site for i in cl})) * 22
    authority = max(i.weight for i in cl) * 7
    sev = SEV_BOOST[severity(cl)]
    epss = max(i.max_epss for i in cl) * 18
    rel = min(max(i.relevance for i in cl), 12) * 0.8   # capped: a CVE's 99 shouldn't dominate

    return round((corroboration + authority + sev + epss + rel) * 0.5 ** (age_h / 72), 2)
