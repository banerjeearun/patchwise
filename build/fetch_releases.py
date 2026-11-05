"""Fetch PyPI release history for each package -> data/releases.jsonl.

One row per version: upload date, whether every file was yanked, whether it has any files.

Run: uv run python build/fetch_releases.py   (no token needed)
"""

import json
from pathlib import Path

import httpx

import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from tools.packages import PACKAGES  # noqa: E402

OUT = Path(__file__).parent.parent / "data" / "releases.jsonl"


def main() -> None:
    rows = []
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        for name in PACKAGES:
            data = client.get(f"https://pypi.org/pypi/{name}/json").raise_for_status().json()
            for version, files in data["releases"].items():
                rows.append({
                    "package": name,
                    "version": version,
                    "date": min((f["upload_time_iso_8601"][:10] for f in files), default=None),
                    "yanked": bool(files) and all(f.get("yanked") for f in files),
                    "has_files": bool(files),
                    "source_url": f"https://pypi.org/project/{name}/{version}/",
                })
            print(f"{name:13} {len(data['releases']):4} releases, latest {data['info']['version']}")
    with OUT.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows)} releases to {OUT}")


if __name__ == "__main__":
    main()
