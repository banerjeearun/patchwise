# PatchWise

**When a security advisory hits a Python dependency, PatchWise says whether it really affects
your pinned version, what the smallest upgrade is that clears *every* known advisory, and what
changes on the way there, with a citation for each claim.**

- **Live app:** https://patchwise-git-177209096392.europe-west1.run.app (Columbia sign-in, through IAP)
- **Course path:** Deep Research (Agentic AI, Project 2). Author: ab6130.

---

## Who it's for

A developer or on-call engineer looking at a security alert (Dependabot, `pip-audit`, a CVE in
Slack) who has to decide **today** what to upgrade. It helps most when the team can't take a
major-version upgrade this sprint, for example on Django 4.2 LTS, and needs to know:

1. Does this advisory actually apply to my version?
2. Is there a fix on my current release line (a backport)? If not, what's the best partial fix there?
3. What's the smallest version that clears everything, and how big a jump is that (patch, minor or major)?
4. What changes between my version and that target, according to the project's own release notes?
5. What can't the data tell me?

`pip-audit` already lists the fix version for each advisory separately. PatchWise works out one
combined target across all of them, finds the best option on your current line, cites the
release notes for what changes, and says plainly what it couldn't check.

## How to use it

1. Open the app. Paste a `requirements.txt`, drop the file onto the box, or ask about one package
   and one CVE. The tabs above the box hold ready-made examples.
2. A **verdict table** appears within about a second. It's computed in code: affected or not,
   any fix on your line, and the smallest full fix.
3. The **cited report** follows, usually in 40–90 seconds. It can take up to about 2.5 minutes
   when Vertex AI is rate-limiting. Superscript numbers link to the exact
   lines of the changelog, the OSV advisory, or the PyPI release.
4. If the question is vague ("is my stack safe?", or no versions given), PatchWise asks for your
   pins first. Reply in the same box and it combines your answer with what you said before.
5. Open **"How this answer was made"** to see every tool call, grouped by the agent that made it.

**Covered packages (6):** django, urllib3, pillow, aiohttp, starlette, cryptography. Any other
package in your file is listed as **not checked**, which does **not** mean it's safe.

---

## Architecture

```
            ┌─────────────── triage (code) ───────────────┐
 message ──▶│ parse pins · affected? · same-line fix ·     │──▶ verdict table (/triage, ~0.1 s)
            │ best partial · smallest full fix             │
            └──────────────────────┬───────────────────────┘
                                   ▼
                    ┌──────────── Lead ────────────┐
                    │ vague? → "CLARIFY: …"        │
                    │ else: research(pkg) × N      │  one turn, so researchers run in parallel
                    │ gaps? → go back (≤ 2 rounds) │
                    └──┬──────────┬──────────┬─────┘
                       ▼          ▼          ▼
               researcher:django  researcher:pillow  …   fresh context each, ≤ 12 turns
               version tools (code) + changelog search (RAG)
                       └──────────┬──────────┘
                                  ▼
                               Writer  ──▶ citation check (code) ──▶ report + numbered Sources
```

**Agent shapes (at least 3, as the course requires):**

| Shape | Where |
|---|---|
| **Orchestrator / fan-out** | The Lead calls the `research` tool once per package in one turn. Each call is a nested `Runner.run` with a fresh context, so the researchers run at the same time and don't see each other's work. |
| **Iterative gap-filling loop** | After the first round, the Lead may send researchers back for gaps, such as no fix on the user's line. This is capped at `MAX_FOLLOWUP_ROUNDS=2` and `MAX_RESEARCHERS=8` in code. |
| **Tool-using researcher (ReAct)** | Each `researcher:<pkg>` agent has 7 tools: `minimal_safe_version`, `advisories_for`, `is_affected`, `fixes_by_branch`, `notes_for_advisory`, `release_notes` and `search_docs`. |
| **Clarification gate** | The Lead answers `CLARIFY: <question>` when the input has no usable pins. `/chat` keeps the session going so the reply is read together with the first message. |
| **Writer + code verifier** | The Writer only sees the question, the triage table and the findings. Then code checks every citation (see below). |

**If a researcher fails:** a researcher can fail, for example when Vertex returns a 429 rate
limit while several run at once. It is retried with backoff (5 s, then 15 s). If it still fails,
code pulls the release-note passages between the pin and the target, with no model call, so the
report keeps cited "what changes" content. The trace shows these steps as `error` and
`fallback_research`.

**Why the version logic is code, not the model:** whether `4.2.10` falls inside an OSV range
(`introduced` / `fixed` / `last_affected`) is a comparison done with `packaging.version`. The
model decides what to look up and explains the result, but it never computes a verdict.

**Citations are checked in code.** The Writer cites with keys: `[S:chunk_id]` for a changelog
passage, `[A:advisory-id]` for an advisory, `[V:pkg==version]` for a PyPI release. Each key is
resolved against what the tools actually returned in this run, or against the snapshot. Keys
that don't resolve are removed. The ones that survive become numbered links to
**line-anchored, commit-pinned** URLs, for example
`github.com/urllib3/urllib3/blob/c5347bb…/CHANGES.rst?plain=1#L664-L667`.

**Retrieval:**
- Changelogs are split by version heading, then by sub-heading, into chunks of at most 1,800
  characters. Each chunk gets a header naming the package and version.
- Chunks are stored in LanceDB, with a BM25 full-text index plus `bge-small-en-v1.5` embeddings
  (fastembed, run locally) and hybrid search that merges the two rankings with RRF.
- Searches are prefiltered by package and version range (`after < version ≤ up_to`).
- Exact lookups come first: release notes for a given version, and notes that name an advisory
  or sit at its fix version. Semantic search is the fallback for questions like "what breaks".

**Stack:**
- Agents: OpenAI Agents SDK 0.24 with LiteLLM → Vertex AI `gemini-3.5-flash` (all three roles,
  set in `agent/config.py`).
- Server and frontend: FastAPI, with a single-file frontend (`index.html`).
- Deploy: Cloud Run (buildpack), continuously deployed from this repo.

### API

`POST /chat` keeps Project 1's shape:

```json
// request
{"message": "We use urllib3==1.26.17. Does CVE-2023-45803 mean we have to move to v2?", "session_id": null}
// response
{"response": "…markdown report with numbered Sources…",
 "session_id": "3f1c…",
 "tool_calls": [{"agent": "lead", "name": "research", "args": {...}, "result": "..."},
                {"agent": "researcher:urllib3", "name": "fixes_by_branch", "args": {...}, "result": "..."},
                {"agent": "writer", "name": "write_report", ...},
                {"agent": "code", "name": "citation_check", ...}]}
```

Other routes:
- `POST /triage`: the code-only verdicts the page shows right away.
- `POST /clear`
- `GET /health`: returns the package list and the advisory count.

---

## Data

A frozen snapshot, **dated 2026-11-05**, is built offline and shipped in `data/` (about 10 MB).
The app makes no network calls for data at runtime.

| File | Source | Size |
|---|---|---|
| `data/advisories.jsonl` | [OSV API](https://osv.dev) (`/v1/query` + `/v1/vulns/{id}`), PyPI ecosystem. Records are merged across aliases (GHSA / PYSEC / CVE), and GHSA ranges are used as the basis. | 392 advisories |
| `data/releases.jsonl` | PyPI JSON API (`pypi.org/pypi/<pkg>/json`), with yanked releases flagged | 1,345 releases |
| `data/docs_raw/` | Each project's changelog or release-note files, fetched **at a pinned commit** (listed in `manifest.json`), plus Pillow's GitHub Releases | 181 files |
| `data/lancedb/` | Chunked + embedded changelogs (built by `build/index.py`) | 2,602 chunks |

**Why GHSA ranges instead of PYSEC:** some PYSEC records give ranges that are too wide. For
example, they flag Django LTS patch releases that already contain the fix. When an advisory has
both, PatchWise uses the GHSA range and keeps the PYSEC one as `alt_ranges`.

**Rebuilding the snapshot** (only needed to refresh the data; the app never needs a token):

```bash
uv run python build/fetch_releases.py
uv run python build/fetch_advisories.py
GITHUB_TOKEN=... uv run python build/fetch_changelogs.py   # token only raises GitHub's rate limit
uv run python build/index.py
```

**Adding a package:** add one entry to `tools/packages.py`. The entry needs the repo, what
counts as a "release line" (minor or major), and the changelog paths. Then rerun the four build
scripts.

---

## Sample queries: expected answer, source, and the agent vs. the same model with no tools

The **expected answers** come from the snapshot records named in each row, and you can check
them by hand at the linked URLs. The no-tools column is the same model (`gemini-3.5-flash` on
Vertex AI), given the same message with **no tools and no system prompt**.

The full, unedited text of both answers for every query is in
[`samples/outputs.md`](samples/outputs.md). It was generated on 2026-11-11.

The times below were measured with no throttling. When Vertex AI rate-limits the project,
retries and backoff can make a report take up to about **2.5 minutes**. The instant verdict
table is not affected.

### 1. One CVE, one pin

> We use urllib3==1.26.17. Does CVE-2023-45803 mean we have to move to v2?

**Expected:** **No, not for this CVE.** It's fixed on the 1.x line in **1.26.18** (and in 2.0.7
on 2.x). But the pin is affected by **9** advisories. The best release on 1.x is **1.26.19**,
which clears 2 of them, and 7 have **no 1.x fix at all**. Clearing everything takes **2.8.0**,
a major jump.

**Source:**
- [OSV GHSA-g4mx-q9vg-27p4](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4) (alias
  CVE-2023-45803): fixed at 1.26.18 and 2.0.7.
- [urllib3 CHANGES.rst, lines 664–667](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L664-L667).
- The 7 advisories with no 1.x fix, for example
  [GHSA-pq67-6m6q-mj2v](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v) and
  [GHSA-2xpw-w6gg-jr37](https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37), are in
  `data/advisories.jsonl`.

| | No tools (9.6 s) | PatchWise (32 s, 10 tool calls) |
|---|---|---|
| Is the pin affected by this CVE? | Yes; fixed in 1.26.18 ✅ | Yes; fixed in 1.26.18 ✅ |
| Do they need v2? | "No… upgrade to the latest 1.26.x (1.26.20). This will fix CVE-2023-45803 **without introducing breaking changes**" | No for this CVE. But **9 advisories** affect the pin, and clearing all of them takes **2.8.0 (major)**. 1.26.19 is the best release on 1.x and leaves 7 ✅ |
| Other advisories | Mentions one (CVE-2024-37891). Implies staying on 1.26.x is safe, but **1.26.20 is still affected by 7 advisories** in the snapshot ❌ | Lists the count and the 1.x ceiling ✅ |
| What changes | General warning about v2 breaking changes, no source | 303-redirect body stripping and `Proxy-Authorization` stripping, each linked to exact `CHANGES.rst` lines ✅ |
| Citations | None | 6, all resolved by the citation check |

### 2. Django LTS, no major upgrade allowed

> We're on django==4.2.10 and can't do a major upgrade this sprint. What's the smallest upgrade
> that fixes the known security advisories, and what changes?

**Expected:** The pin is affected by **45** advisories. The best release on 4.2 is **4.2.30**,
a patch jump that clears **37**. **8** advisories (published June–August 2026, for example
GHSA-923m-gv2p-w5qp on the cache Vary header and GHSA-h7pc-vwp9-298g on signed-cookie salt)
have **no 4.2 fix**. Clearing all of them takes **5.2.17**.

**Source:**
- `data/advisories.jsonl`: the GHSA ranges for these advisories.
- `data/releases.jsonl`: the Django releases on PyPI.
- [Django 4.2.30 release notes](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.30.txt?plain=1#L2-L8).
- Check any single advisory at `osv.dev/vulnerability/<id>`.

| | No tools (15 s) | PatchWise (38 s, 11 tool calls) |
|---|---|---|
| Recommended version | **4.2.19**, "to fix all currently known security advisories" ❌. Our code finds 4.2.19 still affected by **31** advisories, and 4.2.30 exists. | **4.2.30**: clears 37 of 45 ✅ |
| What's left | Claims "zero breaking API changes", with nothing remaining | **8 remain with no 4.2 fix**, named. Full fix is **5.2.17** (major) ✅ |
| CVE IDs | Lists 12 CVEs. **2 of them (CVE-2025-24933, CVE-2025-23011) aren't in OSV's Django records at all** ❌ | Only IDs taken from tool output; unresolvable keys are removed by code ✅ |
| What changes | Summarizes CVE themes, no source | `URLField.to_python()` normalization change, 500-char language-code limit, `os.chmod` in file storage, each linked to release-note lines ✅ |

### 3. A requirements file (parallel fan-out)

```text
# requirements.txt
starlette==0.36.0
aiohttp==3.10.2
urllib3==2.2.1
```

**Expected:**

| Package | Advisories affecting the pin | Fix on its own line | Smallest full fix |
|---|---|---|---|
| starlette 0.36.0 | 7 | none | **1.3.1** (major) |
| aiohttp 3.10.2 | 42 | 3.10.11 clears only 1 | **3.14.4** (minor) |
| urllib3 2.2.1 | 9 | **2.8.0** | **2.8.0** (minor) |

**Source:** `data/advisories.jsonl` and `data/releases.jsonl`. The same figures appear in the
page's instant verdict table, computed by `agent/triage.py`.

| | No tools (8 s) | PatchWise (65 s, 33 tool calls; 3 researchers in parallel) |
|---|---|---|
| starlette | "**Safe**" ❌ (7 advisories affect 0.36.0) | 7 advisories, no fix on 0.36, **1.3.1**. Breaking changes cited from the release notes (`TestClient` `app` / `allow_redirects` removed) ✅ |
| aiohttp | One CVE, fix 3.10.11 ⚠️ (that release clears 1 of 42) | 42 advisories. 3.10.11 is only a partial fix. **3.14.4** clears all ✅ |
| urllib3 | One CVE, "upgrade to ≥2.2.2" ❌ (9 advisories, need 2.8.0) | 9 advisories, **2.8.0** ✅ |
| Advice | Suggests switching pins to `>=` ranges | Per-package "check before upgrading" plus "can't tell from the data" |

**What the comparison shows:** the model alone knows the famous CVEs and gets query 1's headline
right. It fails wherever the answer depends on **recent** advisories, **counting** across
advisories, or **which release lines got backports**, and it makes up confident specifics such
as non-existent CVE IDs and "zero breaking changes". PatchWise takes 3–7 times longer but gets
every expected value above, and every claim links to a record you can check.

### Does retrieval matter? Ablation run

The verdict facts (affected or not, counts, target versions) come from structured data checked
in code. So what do retrieval and the researchers add? To find out, we reran the same 3 queries
with the researchers limited to the 4 version tools: no changelog search, no release-note
lookups, and no code fallback. The full text is in
[`samples/no_retrieval.md`](samples/no_retrieval.md).

| | Full PatchWise | Without retrieval |
|---|---|---|
| Release-note citations (Q1 / Q2 / Q3) | **2 / 4 / 18** | **0 / 0 / 0** |
| Verdicts and target versions | correct | still correct (they come from code) |
| "What changes" contents | Concrete behavior changes from the release notes: 1.26.19 strips `Proxy-Authorization`; Django's `URLField.to_python()` normalization and the 500-character language-code limit; Starlette removed `TestClient(app=…)` and `allow_redirects` and changed the type of `methods` | Only restates the **advisory summaries** ("resolves request smuggling", "fixes 37 advisories"). No API or behavior changes, and twice says the release notes weren't analyzed. |
| "Check before upgrading" | Specific things to grep for or test (`TestClient` calls, custom URL validators) | Generic, or based only on advisory text |

So the version data answers *whether* and *to what*. Retrieval answers **what will break when
you do it**, which is the question `pip-audit` and the plain model can't answer. The page
reflects this: the instant table shows the verdicts, and the report leads with **What changes on
the way**. Each changelog source shows a verbatim quote of the cited lines, which code takes from
the passage text, not the model.

**Clarification (not one of the 3 graded samples):** "Is my stack safe?" gets a clarifying
question asking for the pinned versions in about 6 s, with no research.

---

## Run it locally

```bash
uv sync
gcloud auth application-default login     # Vertex AI credentials; the project comes from gcloud's default
# .env is optional: GITHUB_TOKEN is only used by build/fetch_changelogs.py
uv run python app.py                       # http://localhost:8000
uv run pytest -q                           # 29 tests: version ranges, chunking, retrieval
```

The tests cover the parts where a wrong answer would look plausible:
- OSV range edge cases (`last_affected`, several ranges, prereleases, yanked releases).
- Choosing the best partial fix on a line.
- Splitting changelogs by version heading.
- Retrieval finding the right fix passage among the top results.

## Limitations

- **Six packages only.** Anything else is reported as *not checked*. For full coverage, use
  [osv.dev](https://osv.dev) or `pip-audit`.
- **Direct pins only.** PatchWise doesn't resolve transitive dependencies, `>=` ranges or lock files.
- **It can't see your code.** It can't tell whether you actually use the vulnerable feature, and
  says so.
- **Snapshot cutoff (2026-11-05).** Advisories and releases published after that date are
  missing. The page shows the snapshot date.
- **Release notes vary in depth.** Patch releases often say only "security fixes". The report
  says when the notes are too thin to say what breaks, instead of guessing.
- **"Release line" is a per-package setting.** It's the minor version for Django, aiohttp and
  Starlette, and the major version for urllib3, Pillow and cryptography. A project's real
  support policy can differ.
- **No end-of-life data.** The agent is told not to claim a line is end-of-life, because the
  snapshot doesn't contain that information.
- **No formal eval suite yet.** Correctness rests on unit tests of the code-computed verdicts
  plus the hand-checked samples above.

## Future work

- An eval set generated from OSV ranges (affected or not, smallest fix), scored against the
  agent's final report. Compare retrieval with vector only, vector + filter, and hybrid search.
- More packages (requests, jinja2, werkzeug, setuptools), and resolving lock files and
  transitive dependencies.
- Streaming researcher progress to the page (SSE) instead of one response at the end.
- A cross-encoder reranker for the "what breaks" searches.

## Repo layout

```
app.py              FastAPI: /chat, /triage, /health, serves index.html
index.html          the frontend (single file)
agent/              config.py (models, caps) · triage.py (code verdicts) · team.py (Lead, Researchers, Writer, citations)
tools/              versions.py (OSV range logic) · search.py (LanceDB retrieval) · chunking.py · embed.py · packages.py
build/              offline snapshot builders
data/               the snapshot (advisories, releases, changelogs, LanceDB index)
tests/              pytest
scripts/            check_packages.py (how the 6 packages were chosen)
```
