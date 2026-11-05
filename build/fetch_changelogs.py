"""Fetch changelogs and release notes -> data/docs_raw/<package>/ + data/docs_raw/manifest.json.

Files are fetched at a pinned commit, so every citation URL points at the exact text we indexed
(a github.com/.../blob/<sha>/... permalink), even after upstream edits the file.

Run: uv run python build/fetch_changelogs.py   (needs GITHUB_TOKEN in .env)
"""

import json
import os
import re
from pathlib import Path

import httpx
from dotenv import load_dotenv
from packaging.version import InvalidVersion, Version

import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from tools.packages import PACKAGES  # noqa: E402

ROOT = Path(__file__).parent.parent
OUT = ROOT / "data" / "docs_raw"
load_dotenv(ROOT / ".env")


def version_from_filename(name: str) -> Version | None:
    m = re.match(r"^(\d+(?:\.\d+)*)\.(rst|txt|md)$", name)
    if not m:
        return None
    try:
        return Version(m.group(1))
    except InvalidVersion:
        return None


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN missing from .env")
    gh = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    manifest: dict[str, dict] = {}
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        for name, cfg in PACKAGES.items():
            repo = cfg["repo"]
            branch = client.get(f"https://api.github.com/repos/{repo}", headers=gh).raise_for_status().json()["default_branch"]
            sha = client.get(f"https://api.github.com/repos/{repo}/commits/{branch}", headers=gh).raise_for_status().json()["sha"]
            min_v = Version(cfg.get("min_version", "0"))
            paths = []
            for entry in cfg["changelog"]:
                if not entry.endswith("/"):
                    paths.append(entry)
                    continue
                listing = client.get(f"https://api.github.com/repos/{repo}/contents/{entry.rstrip('/')}",
                                     params={"ref": sha}, headers=gh).raise_for_status().json()
                for item in listing:
                    v = version_from_filename(item["name"])
                    if item["type"] == "file" and v is not None and v >= min_v:
                        paths.append(entry + item["name"])
            files = []
            pkg_dir = OUT / name
            pkg_dir.mkdir(parents=True, exist_ok=True)
            for path in paths:
                text = client.get(f"https://raw.githubusercontent.com/{repo}/{sha}/{path}").raise_for_status().text
                local = pkg_dir / path.replace("/", "__")
                local.write_text(text)
                files.append({"path": path, "local": str(local.relative_to(ROOT)),
                              "source_url": f"https://github.com/{repo}/blob/{sha}/{path}"})
            if cfg.get("github_releases"):
                releases, page = [], 1
                while page <= 5:
                    batch = client.get(f"https://api.github.com/repos/{repo}/releases",
                                       params={"per_page": 100, "page": page}, headers=gh).raise_for_status().json()
                    if not batch:
                        break
                    releases += [{"tag": r["tag_name"], "date": (r.get("published_at") or "")[:10],
                                  "body": r.get("body") or "", "source_url": r["html_url"]}
                                 for r in batch if not r.get("draft")]
                    page += 1
                local = pkg_dir / "github_releases.json"
                local.write_text(json.dumps(releases, indent=1))
                files.append({"path": "github_releases", "local": str(local.relative_to(ROOT)),
                              "source_url": f"https://github.com/{repo}/releases"})
            manifest[name] = {"repo": repo, "commit": sha, "files": files}
            print(f"{name:13} {len(files):4} files @ {sha[:10]}")
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1))


if __name__ == "__main__":
    main()
