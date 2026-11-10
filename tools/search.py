"""Retrieval over changelogs and release notes (LanceDB).

Three ways in, from most to least exact:
  release_notes(package, version)          exact lookup: every chunk for one release
  notes_for_advisory(package, advisory_id) exact: chunks that name the advisory (any alias),
                                           plus the notes of each release that fixed it
  search_docs(query, package, after, upto) ranked: filtered to package + version range, then
                                           hybrid (vector + BM25) ranking inside that set

search_docs takes a `mode` so experiment E1 can compare the three retrieval designs:
  "vector"          plain top-k over everything (the baseline)
  "vector_filtered" + package / version-range prefilter
  "hybrid"          + BM25 keyword scores fused with vectors (reciprocal rank fusion)
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import lancedb

from tools.embed import embed_query
from tools.packages import PACKAGES
from tools.versions import fixes_by_branch, parse, store

DB = Path(__file__).parent.parent / "data" / "lancedb"
ID_OK = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[2-9cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+)$", re.I)
FIELDS = ["chunk_id", "package", "version", "release_date", "source_type", "section", "text", "source_url"]


@lru_cache(maxsize=1)
def table():
    return lancedb.connect(DB).open_table("chunks")


def _key(v: str) -> str | None:
    pv = parse(v)
    return f"{pv.major:04d}.{pv.minor:04d}.{pv.micro:04d}" if pv else None


def _clean(rows: list[dict]) -> list[dict]:
    return [{k: r[k] for k in FIELDS} | ({"score": round(float(r["_relevance_score"]), 4)}
            if "_relevance_score" in r else {}) for r in rows]


def _check(package: str) -> str | None:
    if package not in PACKAGES:
        return f"'{package}' is not in this snapshot. Covered packages: {', '.join(PACKAGES)}."
    return None


def release_notes(package: str, version: str, limit: int = 12) -> dict:
    """Every indexed chunk for one release, in document order."""
    package = package.strip().lower()
    if err := _check(package):
        return {"error": err}
    if parse(version) is None:
        return {"error": f"'{version}' is not a valid version."}
    rows = (table().search().where(f"package = '{package}' AND version = '{parse(version)}'")
            .limit(limit).to_list())
    if not rows:  # "4.2" vs "4.2.0": try the zero-padded key
        rows = table().search().where(f"package = '{package}' AND version_key = '{_key(version)}'").limit(limit).to_list()
    return {"package": package, "version": version, "count": len(rows), "passages": _clean(rows)}


def notes_for_advisory(package: str, advisory_id: str, limit: int = 8) -> dict:
    """Release-note passages about one advisory: chunks naming it (or an alias), then the notes of
    the earliest fix on each release line. Many changelogs never name the CVE, so the second part
    is what usually finds the right text."""
    package = package.strip().lower()
    if err := _check(package):
        return {"error": err}
    adv = store().advisory(package, advisory_id)
    if adv is None:
        return {"error": f"No advisory '{advisory_id}' for {package} in this snapshot."}
    ids = [i.upper() for i in adv.ids if ID_OK.match(i)]
    like = " OR ".join(f"advisory_ids LIKE '%|{i}|%'" for i in ids)
    named = table().search().where(f"package = '{package}' AND ({like})").limit(limit).to_list()
    fix_versions = [ln["earliest_fix"] for ln in fixes_by_branch(package, adv.id)["lines"].values() if ln["earliest_fix"]]
    seen = {r["chunk_id"] for r in named}
    at_fix = []
    for v in fix_versions[-4:]:  # the newest lines are the ones people are on
        for r in release_notes(package, v, limit=6)["passages"]:
            if r["chunk_id"] not in seen:
                seen.add(r["chunk_id"])
                at_fix.append(r)
    return {"package": package, "advisory": adv.brief(), "fix_versions": fix_versions,
            "naming_the_advisory": _clean(named), "at_fix_releases": at_fix[:limit]}


def search_docs(query: str, package: str | None = None, after_version: str | None = None,
                up_to_version: str | None = None, k: int = 5, mode: str = "hybrid") -> dict:
    """Ranked search. Range is (after_version, up_to_version]: "what changed after my pin, up to
    the target". Prereleases are left out."""
    if mode not in ("vector", "vector_filtered", "hybrid"):
        return {"error": f"unknown mode {mode}"}
    where = None
    if mode != "vector":
        if package is None:
            return {"error": "package is required"}
        package = package.strip().lower()
        if err := _check(package):
            return {"error": err}
        clauses = [f"package = '{package}'", "is_prerelease = false"]
        for v, op in ((after_version, ">"), (up_to_version, "<=")):
            if v:
                if (key := _key(v)) is None:
                    return {"error": f"'{v}' is not a valid version."}
                clauses.append(f"version_key {op} '{key}'")
        where = " AND ".join(clauses)
    vec = embed_query(query)
    if mode == "hybrid":
        q = table().search(query_type="hybrid").vector(vec).text(query)
    else:
        q = table().search(vec)
    if where:
        q = q.where(where, prefilter=True)
    rows = q.limit(k).to_list()
    return {"query": query, "package": package, "after_version": after_version,
            "up_to_version": up_to_version, "mode": mode, "passages": _clean(rows)}
