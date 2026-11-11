"""E1: does retrieval put the right release note near the top, and does each design choice help?

No model calls: queries are embedded locally, so this runs in about a minute with no API cost.

Samples are generated from the snapshot, one per advisory (no hand-picking, none used in any prompt):
  Set A "describe"  query = the advisory's summary (what a user pastes from an alert)
  Set B "id"        query = only the advisory's CVE ID (else GHSA ID), e.g. "CVE-2024-47874"

Gold, from the snapshot:
  strict   chunks whose text names the advisory or one of its aliases (index column advisory_ids)
  lenient  strict, plus any chunk from a release that fixed the advisory (fix versions from OSV ranges)

Arms (tools/search.py `mode`):
  vector           plain top-k over all 2,602 chunks, no filter
  vector_filtered  + prefilter: package, and versions after the earliest affected release
  hybrid           + BM25 keyword search fused with the vectors by RRF  (what PatchWise uses)

Metrics: hit@5 (any gold chunk in the top 5) and MRR@10, with the course's margin of error 1/sqrt(n).

Run:  uv run python evals/retrieval_eval.py      -> evals/results_retrieval.json + a markdown table
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packaging.version import InvalidVersion, Version  # noqa: E402

from tools import search, versions  # noqa: E402

K = 10
ARMS = ["vector", "vector_filtered", "hybrid"]
OUT = Path(__file__).parent / "results_retrieval.json"


def chunks_at(package: str, version: str) -> set[str]:
    return {p["chunk_id"] for p in search.release_notes(package, version, limit=50)["passages"]}


def earliest_affected(adv) -> str | None:
    """A realistic old pin: the earliest affected release we have notes for (the filter's lower bound)."""
    vs = []
    for v in adv.versions or []:
        try:
            vs.append(Version(str(v)))
        except InvalidVersion:
            continue
    return str(min(vs)) if vs else None


def build_samples() -> list[dict]:
    samples = []
    s = versions.store()
    for pkg, advs in s.advisories.items():
        for adv in advs:
            notes = search.notes_for_advisory(pkg, adv.id)
            if "error" in notes:
                continue
            strict = {p["chunk_id"] for p in notes["naming_the_advisory"]}
            lenient = set(strict)
            for v in notes["fix_versions"]:
                lenient |= chunks_at(pkg, v)
            if not lenient:
                continue  # no release notes in the snapshot for this advisory: nothing to retrieve
            after = earliest_affected(adv)
            # The pin must be before every fix, or the version filter would hide the gold.
            fixes = [Version(v) for v in notes["fix_versions"]]
            if after and fixes and Version(after) >= min(fixes):
                after = None
            cve = next((i for i in adv.ids if i.upper().startswith("CVE-")), None)
            ghsa = next((i for i in adv.ids if i.upper().startswith("GHSA-")), None)
            base = {"package": pkg, "advisory": adv.id, "after": after, "strict": sorted(strict),
                    "lenient": sorted(lenient)}
            if adv.summary:
                samples.append(base | {"set": "describe", "query": adv.summary.strip()})
            if strict and (cve or ghsa):
                samples.append(base | {"set": "id", "query": (cve or ghsa).upper()})
    return samples


def score(ranked: list[str], gold: set[str]) -> tuple[int, float]:
    hit5 = int(any(c in gold for c in ranked[:5]))
    rr = next((1 / (i + 1) for i, c in enumerate(ranked[:K]) if c in gold), 0.0)
    return hit5, rr


def main() -> None:
    samples = build_samples()
    rows = []
    for smp in samples:
        for arm in ARMS:
            r = search.search_docs(smp["query"], package=smp["package"], after_version=smp["after"], k=K, mode=arm)
            ranked = [p["chunk_id"] for p in r.get("passages", [])]
            for gold_name in ("strict", "lenient"):
                gold = set(smp[gold_name])
                if not gold:
                    continue
                h, rr = score(ranked, gold)
                rows.append({"set": smp["set"], "gold": gold_name, "arm": arm, "advisory": smp["advisory"],
                             "package": smp["package"], "hit5": h, "rr": rr})

    summary = []
    for st in ("describe", "id"):
        for gold_name in ("strict", "lenient"):
            if st == "id" and gold_name == "lenient":
                continue  # an ID query is about the text naming it
            sel = [r for r in rows if r["set"] == st and r["gold"] == gold_name]
            if not sel:
                continue
            n = len(sel) // len(ARMS)
            line = {"set": st, "gold": gold_name, "n": n, "margin": round(1 / math.sqrt(n), 3)}
            for arm in ARMS:
                a = [r for r in sel if r["arm"] == arm]
                line[arm] = {"hit5": round(sum(r["hit5"] for r in a) / n, 3), "mrr": round(sum(r["rr"] for r in a) / n, 3)}
            summary.append(line)

    OUT.write_text(json.dumps({"k": K, "summary": summary, "samples": samples, "rows": rows}, indent=1))
    print("| Query set | Gold | n | ±1/√n | vector | + filter | + hybrid (prod) |")
    print("|---|---|---|---|---|---|---|")
    for s in summary:
        cells = [f"{s[a]['hit5']:.2f} / {s[a]['mrr']:.2f}" for a in ARMS]
        print(f"| {s['set']} | {s['gold']} | {s['n']} | {s['margin']:.2f} | " + " | ".join(cells) + " |")
    print("\ncells: hit@5 / MRR@10")


if __name__ == "__main__":
    main()
