"""Code-checked version logic. No LLM decides whether a version is affected or what fixes it.

Inputs are the frozen snapshot: data/advisories.jsonl (OSV) and data/releases.jsonl (PyPI).

How "affected" works (OSV spec, ECOSYSTEM ranges):
  Walk a range's events in version order. `introduced` at or below v turns it on; `fixed` at or
  below v turns it off; `last_affected` strictly below v turns it off. A version is affected by an
  advisory if any of its ranges (from any merged GHSA/PYSEC record) or its explicit `versions`
  list says so. Taking the union is the conservative choice for a security tool.

Every answer is computed over *real releases* from PyPI, so a "fix" is always a version you can
actually install (not yanked, has files), never a string copied from an advisory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from packaging.version import InvalidVersion, Version

from tools.packages import PACKAGES

DATA = Path(__file__).parent.parent / "data"


def parse(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


@dataclass(frozen=True)
class Release:
    version: Version
    raw: str
    date: str | None
    yanked: bool
    has_files: bool

    @property
    def installable(self) -> bool:
        return self.has_files and not self.yanked


@dataclass
class Advisory:
    package: str
    id: str
    ids: list[str]
    summary: str
    published: str
    ranges: list[dict]
    versions: list[str]
    source_url: str
    raw: dict = field(repr=False, default_factory=dict)

    @cached_property
    def _parsed_ranges(self) -> list[tuple[str, list[tuple[Version, str]]]]:
        out = []
        for rng in self.ranges:
            events = []
            for e in rng["events"]:
                for kind in ("introduced", "fixed", "last_affected"):
                    if kind in e and (pv := parse(e[kind])) is not None:
                        events.append((pv, kind))
            # Ties: process `introduced` before `fixed` so [x, x) is empty, as OSV intends.
            events.sort(key=lambda t: (t[0], t[1] != "introduced"))
            out.append((rng["source"], events))
        return out

    @cached_property
    def _version_list(self) -> set[Version]:
        return {pv for v in self.versions if (pv := parse(v)) is not None}

    def matched_ranges(self, v: Version) -> list[dict]:
        hits = []
        for source, events in self._parsed_ranges:
            on, start = False, None
            for ev, kind in events:
                if kind == "introduced" and v >= ev:
                    on, start = True, ev
                elif kind == "fixed" and v >= ev:
                    on = False
                elif kind == "last_affected" and v > ev:
                    on = False
            if on:
                end = next(((str(ev), k) for ev, k in events if ev > v and k != "introduced"), None)
                hits.append({"source": source, "introduced": str(start),
                             **({end[1]: end[0]} if end else {"fixed": None})})
        return hits

    def affects(self, v: Version) -> bool:
        return v in self._version_list or bool(self.matched_ranges(v))

    def brief(self) -> dict:
        return {"id": self.id, "aliases": [i for i in self.ids if i != self.id], "summary": self.summary,
                "published": self.published[:10], "source_url": self.source_url}


class Store:
    """All releases and advisories, indexed by package. Tests build one from synthetic rows."""

    def __init__(self, releases: list[dict], advisories: list[dict], packages: dict | None = None):
        self.packages = packages or PACKAGES
        self.releases: dict[str, list[Release]] = {}
        for r in releases:
            if (pv := parse(r["version"])) is not None:
                self.releases.setdefault(r["package"], []).append(
                    Release(pv, r["version"], r.get("date"), r.get("yanked", False), r.get("has_files", True)))
        for rs in self.releases.values():
            rs.sort(key=lambda r: r.version)
        self.advisories: dict[str, list[Advisory]] = {}
        self._by_id: dict[tuple[str, str], Advisory] = {}
        for a in advisories:
            adv = Advisory(a["package"], a["id"], a.get("ids", [a["id"]]), a.get("summary", ""),
                           a.get("published", ""), a.get("ranges", []), a.get("versions", []),
                           a.get("source_url", ""), a)
            self.advisories.setdefault(adv.package, []).append(adv)
            for i in {adv.id, *adv.ids}:
                self._by_id[(adv.package, i.upper())] = adv
        self._affected_cache: dict[str, frozenset[Version]] = {}

    @classmethod
    def from_disk(cls, data_dir: Path = DATA) -> Store:
        def read(name: str) -> list[dict]:
            with (data_dir / name).open() as f:
                return [json.loads(line) for line in f]
        return cls(read("releases.jsonl"), read("advisories.jsonl"))

    # --- lookups ---

    def advisory(self, package: str, advisory_id: str) -> Advisory | None:
        return self._by_id.get((package, advisory_id.strip().upper()))

    def find_advisory(self, advisory_id: str) -> list[Advisory]:
        """Advisory by any ID or alias, across packages (a CVE can name more than one)."""
        key = advisory_id.strip().upper()
        return list({id(a): a for (p, i), a in self._by_id.items() if i == key}.values())

    def release(self, package: str, version: str) -> Release | None:
        pv = parse(version)
        return next((r for r in self.releases.get(package, []) if r.version == pv), None)

    def line(self, package: str, v: Version) -> str:
        how = self.packages.get(package, {}).get("line", "minor")
        return str(v.major) if how == "major" else f"{v.major}.{v.minor}"

    def affected_set(self, adv: Advisory) -> frozenset[Version]:
        if adv.id not in self._affected_cache:
            self._affected_cache[adv.id] = frozenset(
                r.version for r in self.releases.get(adv.package, []) if adv.affects(r.version))
        return self._affected_cache[adv.id]

    def candidates(self, package: str, include_pre: bool = False) -> list[Release]:
        return [r for r in self.releases.get(package, [])
                if r.installable and (include_pre or not (r.version.is_prerelease or r.version.is_devrelease))]


_STORE: Store | None = None


def store() -> Store:
    global _STORE
    if _STORE is None:
        _STORE = Store.from_disk()
    return _STORE


def _check_inputs(s: Store, package: str, version: str | None = None) -> dict | None:
    package = package.strip().lower()
    if package not in s.packages:
        return {"error": f"'{package}' is not in this snapshot. Covered packages: {', '.join(s.packages)}."}
    if version is not None:
        if parse(version) is None:
            return {"error": f"'{version}' is not a valid version number."}
        if s.release(package, version) is None:
            return {"error": f"{package} {version} is not a release on PyPI in this snapshot."}
    return None


def jump(a: Version, b: Version) -> str:
    if a == b:
        return "none"
    if a.major != b.major:
        return "major"
    if a.minor != b.minor:
        return "minor"
    return "patch"


# --- the tools ---


def is_affected(package: str, version: str, advisory_id: str, s: Store | None = None) -> dict:
    """Is package==version inside the advisory's affected ranges?"""
    s = s or store()
    package = package.strip().lower()
    if err := _check_inputs(s, package, version):
        return err
    adv = s.advisory(package, advisory_id)
    if adv is None:
        return {"error": f"No advisory '{advisory_id}' for {package} in this snapshot."}
    v = parse(version)
    ranges = adv.matched_ranges(v)
    return {
        "package": package, "version": version, "advisory": adv.brief(),
        "affected": adv.affects(v),
        "matched_ranges": ranges,
        "in_explicit_version_list": v in adv._version_list,
    }


def advisories_for(package: str, version: str, s: Store | None = None) -> dict:
    """Every advisory in the snapshot that affects package==version."""
    s = s or store()
    package = package.strip().lower()
    if err := _check_inputs(s, package, version):
        return err
    v = parse(version)
    hits = [a.brief() for a in s.advisories.get(package, []) if v in s.affected_set(a)]
    return {"package": package, "version": version, "count": len(hits), "advisories": hits}


def fixes_by_branch(package: str, advisory_id: str, s: Store | None = None) -> dict:
    """For each release line with affected releases: the earliest installable release on that line
    that comes after every affected release on the line, or None if the line was never fixed."""
    s = s or store()
    package = package.strip().lower()
    if err := _check_inputs(s, package):
        return err
    adv = s.advisory(package, advisory_id)
    if adv is None:
        return {"error": f"No advisory '{advisory_id}' for {package} in this snapshot."}
    affected = s.affected_set(adv)
    by_line: dict[str, list[Release]] = {}
    for r in s.releases.get(package, []):
        by_line.setdefault(s.line(package, r.version), []).append(r)
    lines = {}
    for ln, rels in by_line.items():
        hit = [r.version for r in rels if r.version in affected]
        if not hit:
            continue
        last = max(hit)
        fix = next((r for r in rels if r.version > last and r.installable and not r.version.is_prerelease
                    and r.version not in affected), None)
        lines[ln] = {"affected_from": str(min(hit)), "affected_to": str(last),
                     "earliest_fix": fix.raw if fix else None, "fix_date": fix.date if fix else None}
    return {"package": package, "advisory": adv.brief(), "line_definition": s.packages[package]["line"],
            "lines": dict(sorted(lines.items(), key=lambda kv: parse(kv[0]) or Version("0")))}


def minimal_safe_version(package: str, pinned: str, s: Store | None = None) -> dict:
    """The smallest installable release >= pinned that no fixable advisory affects, on the same
    release line and overall. Advisories that still affect the latest release can't be cleared by
    upgrading: they are listed as `unfixable`, not hidden."""
    s = s or store()
    package = package.strip().lower()
    if err := _check_inputs(s, package, pinned):
        return err
    pv = parse(pinned)
    advs = s.advisories.get(package, [])
    cands = s.candidates(package, include_pre=pv.is_prerelease)
    latest = max((r.version for r in s.candidates(package)), default=pv)
    unfixable = [a for a in advs if latest in s.affected_set(a)]
    fixable = [a for a in advs if a not in unfixable]
    affecting = [a for a in advs if pv in s.affected_set(a)]

    def safe(v: Version) -> bool:
        return not any(v in s.affected_set(a) for a in fixable)

    line = s.line(package, pv)
    same = next((r for r in cands if r.version >= pv and s.line(package, r.version) == line and safe(r.version)), None)
    overall = next((r for r in cands if r.version >= pv and safe(r.version)), None)

    def describe(r: Release | None) -> dict | None:
        if r is None:
            return None
        return {"version": r.raw, "date": r.date, "jump": jump(pv, r.version),
                "source_url": f"https://pypi.org/project/{package}/{r.raw}/"}

    # When no release on the line clears everything (e.g. the line reached end of support), the
    # useful answer is the smallest release on the line that clears the most, and what's left.
    best = None
    if same is None:
        def exposure(r: Release) -> list[Advisory]:
            return [a for a in fixable if r.version in s.affected_set(a)]

        # Only releases that clear at least one of the pin's advisories; then fewest total
        # remaining (net exposure, counting newly introduced ones); then the smallest version.
        helpful = [r for r in cands if r.version > pv and s.line(package, r.version) == line
                   and any(a not in exposure(r) for a in affecting)]
        if helpful:
            best_r = min(helpful, key=lambda r: (len(exposure(r)), r.version))
            remaining = exposure(best_r)
            cleared = [a for a in affecting if a not in remaining]
            if cleared:
                best = {**describe(best_r),
                        "cleared": len(cleared),
                        "remaining": [a.brief() for a in remaining if a in affecting],
                        # upgrading can *add* advisories when a later release added vulnerable code
                        "newly_introduced": [a.brief() for a in remaining if a not in affecting]}

    return {
        "package": package, "pinned": pinned, "pinned_line": line,
        "line_definition": s.packages[package]["line"],
        "affecting_pinned": [a.brief() for a in affecting],
        "same_line": describe(same),
        "same_line_best_partial": best,
        "overall": describe(overall),
        "latest": str(latest),
        "unfixable": [a.brief() for a in unfixable if pv in s.affected_set(a)],
    }
