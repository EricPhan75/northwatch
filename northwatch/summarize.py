"""
Cluster -> brief. Free backends, with failover.

No paid API anywhere in the default path.

  gemini      Google AI Studio. ~1,500 req/day, 1M tokens/day on Flash. The most
              headroom of any free tier. No credit card.
              https://aistudio.google.com/apikey  ->  export GEMINI_API_KEY=...
              Caveat: Google may train on free-tier prompts. Irrelevant here — every
              word we send is already-public RSS.

  groq        Fast, but the binding limit is ~6,000 tokens/MINUTE, not the daily cap.
              At ~1.5k tokens/call that's ~4 calls/min, so we pace it.
              https://console.groq.com/keys  ->  export GROQ_API_KEY=...

  cloudflare  10,000 neurons/day (~100-300 generations). You're already on Cloudflare.
              Needs CF_ACCOUNT_ID + CF_API_TOKEN (token scope: Workers AI Read).

  ollama      Your own box. Unlimited, free forever. GitHub Actions can't reach it,
              so run the cron locally (Task Scheduler) if you go this route.

  none        No model. Cards still cluster, still carry CVE/KEV/EPSS/severity.

Failover: --backend auto walks the chain and uses the first one that answers.
Free tiers rot without warning — one provider's tokens-per-minute ceiling changed
inside two months. A chain means your build never breaks because of it.

------------------------------------------------------------------------------
The rules that keep an aggregator from becoming a takedown target. Do not relax
them to save tokens:

  - The excerpt is model INPUT. It is never echoed as output.
  - Every field is abstractive and hard-capped IN CODE. No verbatim sentences.
  - The excerpt is dropped after summarization; it never reaches feed.json.
  - Every card names and links every outlet that carried the story.

Do not shortcut this by rendering the raw RSS description into the card. On a
private reader that's fine — it's what every RSS client does. On a public site
it makes you a republisher of someone else's lede.
------------------------------------------------------------------------------
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable

import requests

GEMINI_MODEL = os.environ.get("NW_GEMINI_MODEL", "gemini-2.0-flash")
GROQ_MODEL = os.environ.get("NW_GROQ_MODEL", "llama-3.1-8b-instant")
CF_MODEL = os.environ.get("NW_CF_MODEL", "@cf/meta/llama-3.1-8b-instruct")
OLLAMA_HOST = os.environ.get("NW_OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("NW_OLLAMA_MODEL", "qwen2.5:7b")

CHAIN = ["gemini", "groq", "cloudflare", "ollama"]

# Groq's tokens-per-minute cap bites long before its daily cap. Pace it.
PACE = {"groq": 8.0, "gemini": 0.6, "cloudflare": 0.5, "ollama": 0.0}


SYSTEM = """You write the daily brief for a security-minded reader who does not
have time to read forty articles.

You will be given metadata about ONE story, as covered by one or more outlets.

Write ORIGINAL prose. The source excerpts are raw input so you understand what
happened. Do NOT reuse the source's sentences, phrasing, or structure. Never
quote. Never lightly reword. Read it, then write it fresh in your own words. If
the excerpt is too thin to do that, say so plainly and keep it short.

Return ONLY a JSON object. No preamble, no markdown fences.

{
  "abstract":   "<=45 words. What happened, plainly. Original phrasing.",
  "why":        "<=25 words. Why this matters to someone who works in security. Empty string if it genuinely doesn't.",
  "action":     "<=18 words, imperative, ONLY if there is something to do (patch, rotate, update). Otherwise empty string.",
  "confidence": "high" | "medium" | "low"
}

Rules:
- Most stories have no action. Leave it empty rather than inventing "stay vigilant".
- `action` when it exists is concrete: "Update Chrome to 141.0.7390.54."
- Do not inflate. A funding round is not a threat. A product launch is not a threat.
- confidence "low" if the excerpt is thin, headline-only, or a lone vendor blog.
"""

FALLBACK = {"abstract": "", "why": "", "action": "", "confidence": "low"}
_FENCE = re.compile(r"^```(?:json)?|```$", re.M)


def _payload(cluster: list[dict]) -> str:
    lead = cluster[0]
    return json.dumps({
        "title": lead["title"],
        "outlets": sorted({c["source_name"] for c in cluster}),
        "cves": sorted({c for i in cluster for c in i["cves"]}),
        "kev_listed": sorted({c for i in cluster for c in i["kev"]}),
        "epss_max": max(i["max_epss"] for i in cluster),
        "vendors": sorted({v for i in cluster for v in i["vendors"]}),
        "source_excerpts": [i["excerpt"] for i in cluster[:3]],
    }, ensure_ascii=False)


def _parse(text: str) -> dict[str, Any]:
    return json.loads(_FENCE.sub("", text).strip())


# ---------------------------------------------------------------------------
# backends
# ---------------------------------------------------------------------------

def _gemini(prompt: str) -> dict[str, Any]:
    key = os.environ["GEMINI_API_KEY"]
    r = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
        params={"key": key},
        json={
            "systemInstruction": {"parts": [{"text": SYSTEM}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 400,
                "responseMimeType": "application/json",
            },
        },
        timeout=60,
    )
    r.raise_for_status()
    return _parse(r.json()["candidates"][0]["content"]["parts"][0]["text"])


def _groq(prompt: str) -> dict[str, Any]:
    r = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {os.environ['GROQ_API_KEY']}"},
        json={
            "model": GROQ_MODEL,
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
            "max_tokens": 400,
        },
        timeout=60,
    )
    r.raise_for_status()
    return _parse(r.json()["choices"][0]["message"]["content"])


def _cloudflare(prompt: str) -> dict[str, Any]:
    acct, tok = os.environ["CF_ACCOUNT_ID"], os.environ["CF_API_TOKEN"]
    r = requests.post(
        f"https://api.cloudflare.com/client/v4/accounts/{acct}/ai/run/{CF_MODEL}",
        headers={"Authorization": f"Bearer {tok}"},
        json={
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": prompt}],
            "max_tokens": 400,
            "temperature": 0.2,
        },
        timeout=90,
    )
    r.raise_for_status()
    return _parse(r.json()["result"]["response"])


def _ollama(prompt: str) -> dict[str, Any]:
    r = requests.post(
        f"{OLLAMA_HOST}/api/chat",
        json={
            "model": OLLAMA_MODEL,
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": prompt}],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 400},
        },
        timeout=180,        # a CPU box is slow, not broken
    )
    r.raise_for_status()
    return _parse(r.json()["message"]["content"])


BACKENDS: dict[str, Callable[[str], dict]] = {
    "gemini": _gemini, "groq": _groq, "cloudflare": _cloudflare, "ollama": _ollama,
}


# ---------------------------------------------------------------------------
# preflight — discovers what's actually configured. Never guesses a model name.
# ---------------------------------------------------------------------------

def _probe(name: str) -> bool:
    try:
        if name == "gemini":
            k = os.environ.get("GEMINI_API_KEY")
            if not k:
                return False
            r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                             params={"key": k}, timeout=15)
            return r.status_code == 200
        if name == "groq":
            k = os.environ.get("GROQ_API_KEY")
            if not k:
                return False
            r = requests.get("https://api.groq.com/openai/v1/models",
                             headers={"Authorization": f"Bearer {k}"}, timeout=15)
            return r.status_code == 200
        if name == "cloudflare":
            return bool(os.environ.get("CF_ACCOUNT_ID") and os.environ.get("CF_API_TOKEN"))
        if name == "ollama":
            r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=8)
            have = {m["name"].split(":")[0] for m in r.json().get("models", [])}
            return OLLAMA_MODEL.split(":")[0] in have
    except Exception:                                           # noqa: BLE001
        return False
    return False


def resolve_chain(backend: str) -> list[str]:
    """`auto` finds every backend you have credentials for, in preference order."""
    if backend == "none":
        print("  backend: none — no model. Clustering, CVE, KEV, EPSS still run.")
        return []

    want = CHAIN if backend == "auto" else [backend]
    live = [b for b in want if _probe(b)]

    for b in want:
        print(f"  {'✓' if b in live else '·'} {b}")
    if not live:
        print("\n  No usable backend. Set GEMINI_API_KEY (free, no card):")
        print("    https://aistudio.google.com/apikey")
        print("  Or run with --backend none.")
    else:
        print(f"  chain: {' -> '.join(live)}")
    return live


def summarize_cluster(cluster: list[dict], chain: list[str]) -> dict[str, Any]:
    """Walk the chain. First backend that answers, wins. A 429 on the free tier
    is expected, not exceptional — that's the whole reason the chain exists."""
    if not chain:
        return dict(FALLBACK)
    prompt = _payload(cluster)
    for name in chain:
        try:
            out = enforce(BACKENDS[name](prompt))
            if PACE.get(name):
                time.sleep(PACE[name])
            return out
        except Exception as exc:                                # noqa: BLE001
            code = getattr(getattr(exc, "response", None), "status_code", "")
            print(f"    {name} failed{f' [{code}]' if code else ''} — next")
    return dict(FALLBACK)


# ---------------------------------------------------------------------------
# caps — enforced here, never left to the model's goodwill
# ---------------------------------------------------------------------------

def word_cap(text: str, n: int) -> str:
    w = (text or "").split()
    return " ".join(w[:n]) + ("…" if len(w) > n else "")


def enforce(brief: dict[str, Any]) -> dict[str, Any]:
    """A 200-word "summary" of someone else's article is a copy. Every model is
    told the limits; every model is held to them here regardless. A free 8B model
    will blow through a word cap without noticing."""
    out = dict(FALLBACK)
    out["abstract"] = word_cap(brief.get("abstract", ""), 45)
    out["why"] = word_cap(brief.get("why", ""), 25)
    out["action"] = word_cap(brief.get("action", ""), 18)
    c = brief.get("confidence")
    out["confidence"] = c if c in {"high", "medium", "low"} else "low"
    return out
