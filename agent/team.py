"""PatchWise's research team: Lead -> parallel Researchers (one per package) -> Writer.

Flow for one request:
  1. triage (code): parse pins, compute affected status and upgrade targets.
  2. Lead: clarify if the input is vague; otherwise call `research` once per package in ONE turn,
     so the SDK runs the researchers concurrently, each in a fresh context. It may go back for
     gaps at most MAX_FOLLOWUP_ROUNDS times.
  3. Writer: one call, after research ends. Sees only the question, triage table and findings.
  4. Citations (code): every [S:..]/[A:..]/[V:..] key is checked against what tools actually
     returned in this run; unknown keys are removed. Survivors become numbered references.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field

from agents import Agent, RunContextWrapper, RunHooks, Runner, function_tool, set_tracing_disabled
from agents.exceptions import MaxTurnsExceeded

from agent import config
from agent.triage import triage
from tools import search, versions

# Traces would upload to OpenAI, which needs an OpenAI key. We're on Gemini; /chat is our trace.
set_tracing_disabled(True)


@dataclass
class Run:
    """One request's shared state. The model never sees it."""
    calls: list[dict] = field(default_factory=list)      # the /chat tool_calls trace
    passages: dict[str, dict] = field(default_factory=dict)  # chunk_id -> passage, for citations
    researchers: int = 0
    findings: list[dict] = field(default_factory=list)


def agent_label(agent: Agent) -> str:
    return agent.name.lower()


class Trace(RunHooks):
    """Records every tool call, from every agent, in the /chat shape plus an `agent` field."""

    async def on_tool_start(self, ctx, agent, tool):
        args = getattr(ctx, "tool_arguments", None)
        try:
            args = json.loads(args) if isinstance(args, str) else (args or {})
        except json.JSONDecodeError:
            args = {"raw": args}
        ctx.context.calls.append({"agent": agent_label(agent), "name": tool.name, "args": args,
                                  "result": None, "_id": getattr(ctx, "tool_call_id", None)})

    async def on_tool_end(self, ctx, agent, tool, result):
        cid = getattr(ctx, "tool_call_id", None)
        for c in reversed(ctx.context.calls):
            if c.get("_id") == cid and c["name"] == tool.name and c["result"] is None:
                c["result"] = str(result)[: config.TOOL_RESULT_CHARS]
                break


def _compact(obj):
    """Shrink what the model reads: advisory briefs to id + short summary, passages to 1,200
    chars. The full records stay in the snapshot; citations resolve against those."""
    if isinstance(obj, dict):
        if "id" in obj and "summary" in obj and "source_url" in obj and "published" in obj:
            return {"id": obj["id"], "summary": (obj["summary"] or "")[:110], "published": obj["published"]}
        if "chunk_id" in obj and "text" in obj:
            return {k: obj[k] for k in ("chunk_id", "version", "section")} | {"text": obj["text"][:1200]}
        return {k: _compact(v) for k, v in obj.items() if k not in ("source_url", "aliases")}
    if isinstance(obj, list):
        return [_compact(x) for x in obj]
    return obj


def _dump(obj) -> str:
    return json.dumps(_compact(obj), default=str)


def _keep_passages(ctx: RunContextWrapper[Run], result: dict) -> dict:
    for key in ("passages", "naming_the_advisory", "at_fix_releases"):
        for p in result.get(key, []) or []:
            ctx.context.passages[p["chunk_id"]] = p
    return result


# --- Researcher tools (all deterministic; thin wrappers over tools/) ---


@function_tool
def minimal_safe_version(package: str, pinned_version: str) -> str:
    """Smallest upgrade that clears every known advisory against a pinned version: on the same
    release line (if any), the best partial fix on the line, and the smallest full fix overall.

    Args:
        package: Package name, e.g. 'django'.
        pinned_version: The exact pinned version, e.g. '4.2.10'.
    """
    return _dump(versions.minimal_safe_version(package, pinned_version))


@function_tool
def advisories_for(package: str, version: str) -> str:
    """Every advisory in the snapshot that affects package==version, with summaries.

    Args:
        package: Package name.
        version: Exact version.
    """
    return _dump(versions.advisories_for(package, version))


@function_tool
def is_affected(package: str, version: str, advisory_id: str) -> str:
    """Whether package==version falls inside one advisory's affected ranges (any ID or alias).

    Args:
        package: Package name.
        version: Exact version.
        advisory_id: GHSA, PYSEC or CVE ID.
    """
    return _dump(versions.is_affected(package, version, advisory_id))


@function_tool
def fixes_by_branch(package: str, advisory_id: str) -> str:
    """For one advisory: the earliest fix on each release line, or null if that line was never fixed.

    Args:
        package: Package name.
        advisory_id: GHSA, PYSEC or CVE ID.
    """
    return _dump(versions.fixes_by_branch(package, advisory_id))


@function_tool
def notes_for_advisory(ctx: RunContextWrapper[Run], package: str, advisory_id: str) -> str:
    """Release-note passages about one advisory: chunks that name it, plus the notes of the
    releases that fixed it. Use this to explain what the fix changed.

    Args:
        package: Package name.
        advisory_id: GHSA, PYSEC or CVE ID.
    """
    return _dump(_keep_passages(ctx, search.notes_for_advisory(package, advisory_id)))


@function_tool
def search_docs(ctx: RunContextWrapper[Run], query: str, package: str, after_version: str | None = None,
                up_to_version: str | None = None) -> str:
    """Search one package's changelogs and release notes, limited to versions in
    (after_version, up_to_version]. Use it for "what changes / what breaks between my pin and the
    target": deprecations, removals, behavior changes.

    Args:
        query: What to look for, e.g. 'removed deprecated API' or 'breaking change'.
        package: Package name.
        after_version: Exclusive lower bound, usually the user's pin.
        up_to_version: Inclusive upper bound, usually the target version.
    """
    return _dump(_keep_passages(ctx, search.search_docs(query, package, after_version, up_to_version, k=6)))


@function_tool
def release_notes(ctx: RunContextWrapper[Run], package: str, version: str) -> str:
    """All release-note passages for one exact version.

    Args:
        package: Package name.
        version: Exact version, e.g. '1.26.18'.
    """
    return _dump(_keep_passages(ctx, search.release_notes(package, version, limit=8)))


RESEARCHER_TOOLS = [minimal_safe_version, advisories_for, is_affected, fixes_by_branch,
                    notes_for_advisory, search_docs, release_notes]

RESEARCHER_INSTRUCTIONS = """\
You research ONE Python package for an engineer triaging security advisories. You get the package,
the pinned version, and a task. Use only facts from your tools; never from memory.

Work fast: call independent tools IN THE SAME TURN (e.g. steps 1 and 2 together, then all doc
lookups together). Use at most 8 tool calls in total, then answer.

Steps:
1. minimal_safe_version(package, pinned) for the targets. If the task names an advisory, also
   is_affected and fixes_by_branch for it.
2. advisories_for(package, pinned) to see what the advisories are about (summaries).
3. Explain what changes: notes_for_advisory for the 1-3 most important advisories, and
   search_docs(query, package, after_version=pinned, up_to_version=target) for deprecations,
   removals and breaking changes on the way to the recommended target. At most 6 doc lookups.

Citations: after every fact, add a key in square brackets, one key per bracket:
- [S:<chunk_id>] for a release-note passage (chunk_id exactly as the tool returned it)
- [A:<advisory id>] for an advisory, e.g. [A:GHSA-xxxx-xxxx-xxxx]
- [V:<package>==<version>] for a version fact, e.g. [V:django==4.2.30]
Never invent a key. If you have no source for a statement, leave the statement out.
Don't call a release line "end-of-life" or "unsupported" unless a passage says so; say "no fix on
<line> in the snapshot" instead.

Reply in this exact shape, under 300 words:
PACKAGE: <name>==<pinned>
VERDICT: affected by N advisories / not affected (and the asked advisory, if any)
RECOMMENDED: <version and jump size; same-line partial if relevant, with what remains>
WHAT CHANGES: 2-5 bullets, each cited
CHECK BEFORE UPGRADING: 1-4 bullets, each cited
CANNOT ANSWER: what the data can't tell (e.g. whether the app uses the vulnerable feature)
GAPS: anything you could not find, or "none"
"""


def make_researcher(package: str) -> Agent:
    return Agent(name=f"researcher:{package}", instructions=RESEARCHER_INSTRUCTIONS,
                 model=config.model(config.RESEARCHER_MODEL), model_settings=config.settings(parallel=True),
                 tools=RESEARCHER_TOOLS)


# --- Lead ---


@function_tool
async def research(ctx: RunContextWrapper[Run], package: str, pinned_version: str, task: str) -> str:
    """Send a researcher to investigate one package in a fresh context. Call this once per package,
    all in the same turn, so they run in parallel. Returns the researcher's findings.

    Args:
        package: One covered package, e.g. 'django'.
        pinned_version: The user's exact pinned version.
        task: What to find out, specific to this package (mention any advisory ID the user asked about).
    """
    run = ctx.context
    if run.researchers >= config.MAX_RESEARCHERS:
        return "No researchers left for this request. Reply DONE."
    run.researchers += 1
    agent = make_researcher(package.strip().lower())
    prompt = f"Package: {package}\nPinned version: {pinned_version}\nTask: {task}"
    out = None
    for attempt in range(2):  # one retry for transient errors (429s, timeouts)
        try:
            result = await Runner.run(agent, prompt, context=run, hooks=Trace(), max_turns=config.RESEARCHER_MAX_TURNS)
            out = str(result.final_output)
            break
        except MaxTurnsExceeded:
            out = (f"Researcher ran out of turns. GAPS: release-note explanations for {package}. "
                   "Do not send another researcher for this package; the writer will use the triage table.")
            break
        except Exception as e:  # one failed researcher must not sink the whole request
            out = f"Researcher failed: {type(e).__name__}: {str(e)[:200]}. GAPS: everything for {package}."
            await asyncio.sleep(2)
    run.findings.append({"package": package, "pinned": pinned_version, "task": task, "findings": out})
    return out


LEAD_INSTRUCTIONS = f"""\
You lead PatchWise, a research team that triages Python security advisories. Covered packages
(and only these): django, urllib3, pillow, aiohttp, starlette, cryptography. You get the user's
message and a TRIAGE table that code computed from a frozen advisory snapshot. Trust the table.

Decide one of:
A) CLARIFY. Reply with "CLARIFY: <one short question>" and nothing else when you can't research
   anything useful, e.g. no exact pins for covered packages (only names, ranges like >=, or
   versions that don't exist), or a vague question ("is my stack safe?") with no requirements.
   Ask for exactly what's missing (an exact pin like django==4.2.10, or a pasted requirements.txt).
   If some pins are usable, research those instead and mention the unusable ones in the end.
B) RESEARCH. Call research once per checked pin that has advisories, ALL IN THE SAME TURN.
   Give each a specific task (mention advisory IDs the user asked about). Skip pins with 0
   advisories: the writer reports them from the table.
   Then read the findings. If a researcher reports GAPS that matter (e.g. no fix on the user's
   line and it didn't explain what breaks in the bigger jump), call research again for just that
   package with a targeted task. Never re-send a researcher that failed or ran out of turns. Do this at most {config.MAX_FOLLOWUP_ROUNDS} times in total.
   When done, reply "DONE" and nothing else. A writer writes the answer.
C) If nothing is researchable but nothing is missing either (every pin has 0 advisories, or only
   uncovered packages), reply "DONE" so the writer reports it.
"""

lead = Agent(name="lead", instructions=LEAD_INSTRUCTIONS, model=config.model(config.LEAD_MODEL),
             model_settings=config.settings(parallel=True), tools=[research])


# --- Writer ---

WRITER_INSTRUCTIONS = """\
You write PatchWise's answer for an engineer, in markdown, using ONLY the triage table and the
researcher findings you're given.

- Start with a 1-3 sentence bottom line.
- Then one section per package: "### <package>==<pinned>", then bullets: **Affected**,
  **Smallest safe upgrade** (say the jump size; if there's a same-line partial fix, give it and
  what remains), **What changes**, **Check before upgrading**, **Can't tell from the data**.
- Pins with 0 advisories: one line saying no advisories in the snapshot affect them.
- Unusable input (ranges, unknown versions, uncovered packages): a short "Not checked" list with why.
  Then say plainly that "not checked" does NOT mean safe, name the covered packages (django,
  urllib3, pillow, aiohttp, starlette, cryptography), and suggest checking the rest with osv.dev or
  pip-audit. Never call it "our database"; say "the PatchWise snapshot".
- Keep the citation keys exactly as given ([S:...], [A:...], [V:...]), one per bracket, after the
  fact they support. Never write a URL. Never add facts that aren't in the findings or table.
- Don't say a release line is end-of-life unless the findings cite a source for it; say "no fix on
  that line in the snapshot".
- Plain, specific sentences. No filler.
"""

writer = Agent(name="writer", instructions=WRITER_INSTRUCTIONS, model=config.model(config.WRITER_MODEL),
               model_settings=config.settings())


# --- Citations (code-checked) ---

BRACKET = re.compile(r"\[([^\[\]]+)\](?!\()")
KEY = re.compile(r"^\s*(S|A|V):\s*(.+?)\s*$")


def resolve(key: str, value: str, run: Run) -> tuple[str, str] | None:
    """(label, url) if the key points at something real in this run / the snapshot, else None."""
    if key == "S" and value in run.passages:
        p = run.passages[value]
        label = f"{p['package']} {p['version']} release notes" + (f": {p['section']}" if p["section"] else "")
        return label, p["source_url"]
    if key == "A":
        found = versions.store().find_advisory(value)
        if found:
            a = found[0]
            return f"{a.id}: {a.summary}"[:140], a.source_url
    if key == "V" and "==" in value:
        pkg, ver = value.split("==", 1)
        if versions.store().release(pkg.strip().lower(), ver.strip()):
            return (f"{pkg.strip()} {ver.strip()}: release on PyPI; affected/fixed status computed by "
                    f"PatchWise from OSV advisory ranges", f"https://pypi.org/project/{pkg.strip()}/{ver.strip()}/")
    return None


def apply_citations(text: str, run: Run) -> tuple[str, dict]:
    numbers: dict[tuple[str, str], int] = {}
    refs: list[tuple[int, str, str]] = []
    dropped: list[str] = []

    def sub(m: re.Match) -> str:
        parts = re.split(r"[;,]\s*(?=[SAV]:)", m.group(1))
        keys = [KEY.match(p) for p in parts]
        if not all(keys):
            return m.group(0)  # ordinary brackets, not citations
        out = []
        for k in keys:
            hit = resolve(k.group(1), k.group(2), run)
            if hit is None:
                dropped.append(f"{k.group(1)}:{k.group(2)}")
                continue
            if hit[1] not in {u for _, _, u in refs}:
                numbers[hit] = len(refs) + 1
                refs.append((numbers[hit], hit[0], hit[1]))
            n = next(n for n, _, u in refs if u == hit[1])
            out.append(f"[{n}]({hit[1]})")
        return "".join(out)

    body = BRACKET.sub(sub, text)
    if refs:
        body += "\n\n**Sources**\n" + "\n".join(f"{n}. [{label}]({url})" for n, label, url in refs)
    return body, {"kept": len(refs), "dropped": dropped}


# --- Entry point ---


async def answer(message: str) -> dict:
    run = Run()
    table = triage(message)
    run.calls.append({"agent": "lead", "name": "triage (code)", "args": {"message": message[:2000]},
                      "result": json.dumps(table)[: config.TOOL_RESULT_CHARS]})
    prompt = f"USER MESSAGE:\n{message}\n\nTRIAGE:\n{json.dumps(table, indent=1)}"
    lead_result = await Runner.run(lead, prompt, context=run, hooks=Trace(), max_turns=config.LEAD_MAX_TURNS)
    decision = str(lead_result.final_output).strip()

    if decision.upper().startswith("CLARIFY"):
        question = decision.split(":", 1)[1].strip() if ":" in decision else decision
        return {"response": question, "tool_calls": _clean(run.calls), "clarify": True}

    findings = "\n\n---\n\n".join(f"{f['findings']}" for f in run.findings) or "(no researchers were needed)"
    w = await Runner.run(writer, f"USER MESSAGE:\n{message}\n\nTRIAGE:\n{json.dumps(table, indent=1)}\n\n"
                                 f"FINDINGS:\n{findings}", context=run, hooks=Trace(), max_turns=2)
    text, check = apply_citations(str(w.final_output), run)
    run.calls.append({"agent": "writer", "name": "write_report", "args": {"findings": len(run.findings)},
                      "result": f"{len(text)} chars"})
    run.calls.append({"agent": "writer", "name": "citation_check (code)", "args": {},
                      "result": json.dumps(check)})
    return {"response": text, "tool_calls": _clean(run.calls), "clarify": False}


def _clean(calls: list[dict]) -> list[dict]:
    return [{k: v for k, v in c.items() if not k.startswith("_")} for c in calls]


async def answer_with_timeout(message: str) -> dict:
    return await asyncio.wait_for(answer(message), timeout=config.REQUEST_TIMEOUT_S)
