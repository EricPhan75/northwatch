# NORTHWATCH

Cybersecurity and tech news, clustered and compressed. Read one screen instead of forty articles.

Same premise as [peek.vn](https://peek.vn) — collapse the day's reading into a feed — pointed at
security. Global, not Canada-only. Tech news is in, but only the tech news that touches security.

**Free to run. No paid API anywhere in the default path.**

```
fetch ─▶ gate ─▶ enrich ─▶ cluster ─▶ score ─▶ brief ─▶ feed.json ─▶ static site
 RSS    cyber-   CVE/KEV    IDF       heat     free      commit      Cloudflare
        relevance  EPSS    cosine              LLM      (Actions)      Pages
```

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m northwatch.cli doctor                     # validate every feed. do this first.
python -m northwatch.cli resolve                    # YouTube @handles -> channel IDs
python -m northwatch.cli build --backend none       # free, no model
cd web && python -m http.server 8000
```

**Run `doctor` first.** Feeds marked `verified: false` in `sources.yaml` are best-known-good but
unconfirmed. Publishers move RSS endpoints without redirects constantly. `doctor` probes them all
and exits non-zero on anything dead. A feed you can't verify is worse than no feed — it fails
silently and you never notice the hole.

---

## Free brief generation

The abstract on each card needs a model. Everything else — clustering, CVE/KEV/EPSS, severity,
the relevance gate — is pure Python and costs nothing.

| `--backend` | Free tier | Get a key |
|---|---|---|
| `gemini` | ~1,500 req/day, 1M tokens/day on Flash. **Most headroom.** | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) — no card |
| `groq` | ~1,000 req/day, but **6,000 tokens/min** is the real ceiling | [console.groq.com/keys](https://console.groq.com/keys) |
| `cloudflare` | 10,000 neurons/day (~100–300 generations) | Workers AI. You're already on Cloudflare. |
| `ollama` | Unlimited, your box | `ollama pull qwen2.5:7b` |
| `none` | — | Cards render bare. Still fully useful. |

```bash
export GEMINI_API_KEY=...
python -m northwatch.cli build --backend auto
```

`auto` walks **gemini → groq → cloudflare → ollama** and uses the first that answers. Free tiers
rot without warning — one provider's tokens-per-minute ceiling changed inside two months. The
chain means a 429 costs you a retry, not a broken build.

Only clusters above `BRIEF_MIN_HEAT` (in `cli.py`) get a brief. Low-heat stories render with
headline, sources and metadata. That's not a cost hack — most stories don't need a paragraph, and
on a free tier it's the difference between finishing the run and hitting a rate limit.

Google may train on free-tier Gemini prompts. Irrelevant here: every word sent is already-public RSS.

---

## The gate

The Verge posts ~40 items a day. Three matter to you. Without a filter the feed is phone reviews
and the security signal drowns.

- **Security-scoped feeds go in raw.** Ars, The Register, TechCrunch and WIRED all publish a
  security-only category feed. Those are pre-filtered by the publisher.
- **General feeds are gated.** Every item scores against a weighted lexicon: 3 points per hard
  security term, 2 per privacy/regulatory term, 1 per adjacent term. Threshold 3.
- **A CVE is an automatic pass.** 
- **Commerce language in the title is an automatic reject** — review, deal, best, vs, unboxing,
  Prime Day. Unless a hard security term also fires. So "Chrome zero-day patched" survives and
  "best password managers of 2026" doesn't, because that second one is affiliate bait wearing a
  security costume.

Measured 8/8 on a realistic headline mix, **zero false admits**. Nothing about phone reviews
reaches you.

`encrypt` and `surveillance` are scored as *hard* security terms, not soft ones. That was a fix,
not a guess: the first build filed them as soft and the gate dropped *"Apple pulls encrypted iCloud
backups in the UK after government order"* — precisely the kind of story this site exists to surface.

Tune with `--threshold N` once you've seen a real day of output.

---

## Clustering

Five outlets covering one story is one card, and the number of outlets is the strongest signal
that a story matters. Two passes:

1. **Shared CVE → same story.** Exact. This is the structural advantage security news has over
   general news.
2. **Otherwise, IDF-weighted cosine** over title + excerpt, headline tokens double-weighted.

The first build used plain title overlap (Jaccard) and it failed on the case that matters most:

```
"Apple pulls end-to-end encrypted iCloud backups in UK after government order"
"Apple withdraws encrypted backups in Britain over encryption backdoor demand"
```

One story. *pulls* vs *withdraws*, *UK* vs *Britain* — three shared words out of thirteen. Jaccard
scored 0.23 and split them into two cards. IDF knows that "Apple" appears in forty items today and
tells you nothing, while "encrypted" and "backups" appear in two and tell you everything. It merges
them. Security news survives a weak similarity function because CVEs rescue it. Tech news does not.

---

## Triage layer

Kept from the v1 build, because it's what makes this a *security* reader and not an RSS client.

| Band | Trigger |
|---|---|
| 🔴 exploited | CVE is in the **CISA KEV catalog** — being used against real targets today |
| 🟠 high | Exploitation language, or **EPSS ≥ 0.50** |
| 🔵 medium | Has a CVE, is an advisory, or is a confirmed incident |
| ⚫ info | Context only |

KEV and EPSS are free, no key, no auth. Together they turn "there are 40 CVEs today" into "these
three matter."

Canada is a **filter**, not a scoring bonus. v1 ranked a Cyber Centre advisory above a global
platform breach, which was wrong for a news reader.

---

## Deploy

Cloudflare Pages + GitHub Actions. No server, no cost.

1. Push to GitHub. Add `GEMINI_API_KEY` (and optionally `NTFY_TOPIC`) as repo secrets.
2. Cloudflare Pages → connect repo → build output `web`, no build command.
3. `.github/workflows/refresh.yml` runs every 3h, rebuilds `feed.json`, commits. Pages redeploys.
4. Point a subdomain at it.

Ollama can't be reached from a GitHub runner. If you want a local model, run the cron on your own
box (Task Scheduler, same pattern as your ntfy script) and push from there.

---

## The part that keeps the site online

Read `summarize.py` before changing it.

- Excerpts are model **input**. Never echoed, never persisted, never in `feed.json`.
- Every field is abstractive and **hard-capped in code** (abstract 45 words, why 25, action 18).
  Free 8B models blow through word limits without noticing, so the cap is enforced, not requested.
- Every card names and links every outlet that carried the story.
- Ingest is publisher-sanctioned RSS only. No scraping article bodies.

Do not shortcut this by rendering the raw RSS `description` into the card. On a private reader
that's fine — it's what every RSS client does. On a public site it makes you a republisher of
someone else's lede, and that's the one change that turns this from a service into a takedown target.

---

## Next

1. **ATT&CK tagging** — have the model emit technique IDs, add a filter.
2. **Sigma rule linking** — when a story names a technique, link the matching SigmaHQ rule.

Both are free. A hiring manager who opens this and sees ATT&CK IDs and Sigma links understands in
four seconds that you can build detection content, not just read about it.
