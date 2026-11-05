"""Fetch OSV advisories for each package -> data/advisories.jsonl.

OSV lists one issue under several IDs (GHSA, PYSEC, CVE). We merge records that share an ID or
alias, keep the GHSA record as the primary one when there is one, and store the union of ranges.

Ranges come from the GHSA record(s) when there is one (see normalize), else from every record.

Run: uv run python build/fetch_advisories.py   (no token needed)
"""

import json
from pathlib import Path

import httpx

import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from tools.packages import PACKAGES  # noqa: E402

OUT = Path(__file__).parent.parent / "data" / "advisories.jsonl"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"


def query_ids(client: httpx.Client, name: str) -> list[dict]:
    vulns, token = [], None
    while True:
        body = {"package": {"name": name, "ecosystem": "PyPI"}}
        if token:
            body["page_token"] = token
        r = client.post(OSV_QUERY, json=body)
        r.raise_for_status()
        data = r.json()
        vulns += data.get("vulns", [])
        token = data.get("next_page_token")
        if not token:
            return vulns


def group(vulns: list[dict]) -> list[list[dict]]:
    """Union-find over IDs and aliases, so A~B and B~C end up in one group."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for v in vulns:
        for a in v.get("aliases", []):
            parent[find(a)] = find(v["id"])
    groups: dict[str, list[dict]] = {}
    for v in vulns:
        groups.setdefault(find(v["id"]), []).append(v)
    return list(groups.values())


def pick_primary(records: list[dict]) -> dict:
    for prefix in ("GHSA-", "PYSEC-"):
        for r in records:
            if r["id"].startswith(prefix):
                return r
    return records[0]


def normalize(name: str, records: list[dict]) -> dict:
    primary = pick_primary(records)
    ids = sorted({r["id"] for r in records} | {a for r in records for a in r.get("aliases", [])})
    # Basis: GitHub-reviewed (GHSA) records when present. PYSEC records are often generated as
    # "everything below the main fix" and miss backports, which would flag fixed LTS releases.
    ghsa = [r for r in records if r["id"].startswith("GHSA-")]
    basis = ghsa or records
    alt_ranges = []
    for r in records:
        if r in basis:
            continue
        for aff in r.get("affected", []):
            if aff.get("package", {}).get("name", "").lower() == name:
                alt_ranges += [{"source": r["id"], "events": g["events"]}
                               for g in aff.get("ranges", []) if g.get("type") == "ECOSYSTEM"]
    ranges, versions = [], set()
    for r in basis:
        for aff in r.get("affected", []):
            if aff.get("package", {}).get("name", "").lower() != name:
                continue
            for rng in aff.get("ranges", []):
                if rng.get("type") == "ECOSYSTEM":
                    ranges.append({"source": r["id"], "events": rng["events"]})
            versions |= set(aff.get("versions", []))
    refs = []
    for r in records:
        for ref in r.get("references", []):
            if ref["url"] not in {x["url"] for x in refs}:
                refs.append({"type": ref.get("type"), "url": ref["url"]})
    return {
        "package": name,
        "id": primary["id"],
        "ids": ids,
        "cves": [i for i in ids if i.startswith("CVE-")],
        "summary": primary.get("summary") or next((r.get("summary") for r in records if r.get("summary")), ""),
        "details": primary.get("details", ""),
        "published": min(r.get("published", "9999") for r in records),
        "modified": max(r.get("modified", "") for r in records),
        "severity": primary.get("severity", []),
        "basis": "ghsa" if ghsa else "all",
        "ranges": ranges,
        "versions": sorted(versions),
        "alt_ranges": alt_ranges,
        "references": refs,
        "source_url": f"https://osv.dev/vulnerability/{primary['id']}",
    }


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        for name in PACKAGES:
            summaries = query_ids(client, name)
            # The query endpoint can trim records; fetch each one in full to be safe.
            full = [client.get(OSV_VULN.format(v["id"])).raise_for_status().json() for v in summaries]
            groups = [normalize(name, g) for g in group(full)]
            groups = [g for g in groups if g["ranges"] or g["versions"]]
            rows += sorted(groups, key=lambda g: g["published"])
            print(f"{name:13} {len(full):4} records -> {len(groups):4} advisories")
    with OUT.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows)} advisories to {OUT}")


if __name__ == "__main__":
    main()
