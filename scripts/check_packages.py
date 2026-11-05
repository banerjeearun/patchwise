"""M1: evaluate candidate packages and print a shortlist table.

For each candidate: advisories published since 2025-01-01 (OSV, PyPI), how many release lines
got a fix, and where the changelog lives. Uses GITHUB_TOKEN from .env only to look at repo files.
The token is never printed.

Run: uv run python scripts/check_packages.py
"""

import os
import re
from pathlib import Path

import httpx
from dotenv import load_dotenv
from packaging.version import InvalidVersion, Version

load_dotenv(Path(__file__).parent.parent / ".env")

SINCE = "2025-01-01"
OSV_QUERY = "https://api.osv.dev/v1/query"

# package -> (github repo, release-line granularity)
CANDIDATES = {
    "urllib3": ("urllib3/urllib3", "major"),
    "requests": ("psf/requests", "minor"),
    "django": ("django/django", "minor"),
    "jinja2": ("pallets/jinja", "minor"),
    "cryptography": ("pyca/cryptography", "major"),
    "pillow": ("python-pillow/Pillow", "minor"),
    "aiohttp": ("aio-libs/aiohttp", "minor"),
    "starlette": ("encode/starlette", "minor"),
    "werkzeug": ("pallets/werkzeug", "minor"),
    "setuptools": ("pypa/setuptools", "major"),
}

CHANGELOG_NAMES = re.compile(r"^(changes|changelog|history|news|release-notes?)(\.(rst|md|txt))?$", re.I)


def release_line(v: str, how: str) -> str | None:
    try:
        p = Version(v)
    except InvalidVersion:
        return None
    return str(p.major) if how == "major" else f"{p.major}.{p.minor}"


def fetch_vulns(client: httpx.Client, name: str) -> list[dict]:
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


def dedupe(vulns: list[dict]) -> list[dict]:
    """OSV lists one issue under several IDs (GHSA, PYSEC, CVE). Merge records that share an ID or alias."""
    groups: list[tuple[set[str], dict]] = []
    for v in vulns:
        ids = {v["id"], *v.get("aliases", [])}
        for g in groups:
            if g[0] & ids:
                g[0].update(ids)
                if len(v.get("affected", [])) > len(g[1].get("affected", [])):
                    g[1].update({"affected": v["affected"]})
                if v.get("published", "9") < g[1].get("published", "9"):
                    g[1]["published"] = v["published"]
                break
        else:
            groups.append((ids, dict(v)))
    return [g[1] for g in groups]


def fixed_versions(vuln: dict, name: str) -> list[str]:
    out = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != name:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return out


def changelog_source(client: httpx.Client, repo: str, headers: dict) -> str:
    found = []
    for path in ("", "docs", "docs/releases", "docs/source"):
        r = client.get(f"https://api.github.com/repos/{repo}/contents/{path}", headers=headers)
        if r.status_code != 200 or not isinstance(r.json(), list):
            continue
        for item in r.json():
            if CHANGELOG_NAMES.match(item["name"]) or (path == "docs/releases" and item["type"] == "file"):
                found.append(f"{path + '/' if path else ''}{item['name']}")
        if path == "docs/releases" and found:
            found = [f for f in found if f.startswith("docs/releases/")]
            return f"docs/releases/ ({len(found)} files)"
    if found:
        return ", ".join(found[:2])
    r = client.get(f"https://api.github.com/repos/{repo}/releases?per_page=1", headers=headers)
    return "GitHub Releases only" if r.status_code == 200 and r.json() else "none found"


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN missing from .env")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    rows = []
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for name, (repo, how) in CANDIDATES.items():
            vulns = dedupe(fetch_vulns(client, name))
            recent = [v for v in vulns if v.get("published", "") >= SINCE]
            lines: set[str] = set()
            multi = 0  # advisories fixed on more than one release line
            for v in recent:
                ls = {release_line(f, how) for f in fixed_versions(v, name)} - {None}
                lines |= ls
                multi += len(ls) > 1
            rows.append((name, len(vulns), len(recent), len(lines), multi, how,
                         changelog_source(client, repo, headers)))

    hdr = ("package", "total", f"since {SINCE[:4]}", "fix lines", "multi-line", "line=", "changelog source")
    print(" | ".join(hdr))
    print("-" * 110)
    for r in rows:
        print(" | ".join(str(x) for x in r))
    print("\nKeep rule: >=2 advisories since 2025, a changelog source, and >=2 of the 6 with multi-line backports.")


if __name__ == "__main__":
    main()
