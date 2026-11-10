"""Chunk every changelog and release note, embed, and write the LanceDB index -> data/lancedb/.

- Only versions that exist on PyPI are indexed (skips unreleased "main" sections).
- Advisory IDs found in a chunk are expanded to all their aliases, so a chunk that says
  "CVE-2024-24680" is also found by its GHSA ID.
- A full-text (BM25) index on `text` makes hybrid search possible.

Run: uv run python build/index.py   (offline, no token; downloads the embedding model once)
"""

import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import lancedb  # noqa: E402

from tools.chunking import Chunk, chunk_changelog, chunk_single_release  # noqa: E402
from tools.embed import embed_passages  # noqa: E402
from tools.versions import Store, parse  # noqa: E402

ROOT = Path(__file__).parent.parent
DB = ROOT / "data" / "lancedb"


def version_key(v: str) -> str:
    """Zero-padded so SQL string comparison sorts like versions: 4.2.10 -> 0004.0002.0010."""
    pv = parse(v)
    return f"{pv.major:04d}.{pv.minor:04d}.{pv.micro:04d}"


def collect() -> list[Chunk]:
    manifest = json.loads((ROOT / "data" / "docs_raw" / "manifest.json").read_text())
    chunks: list[Chunk] = []
    for pkg, m in manifest.items():
        for f in m["files"]:
            local = ROOT / f["local"]
            if f["path"] == "github_releases":
                for r in json.loads(local.read_text()):
                    tag = r["tag"].lstrip("v")
                    if parse(tag):
                        # release pages have no line anchors, so link the page itself
                        chunks += chunk_single_release(pkg, tag, r["body"], True, r["source_url"], permalink_lines=False)
                continue
            text, md = local.read_text(), f["path"].endswith(".md")
            single = re.match(r".*/(\d+(?:\.\d+)+)\.(rst|txt|md)$", f["path"])
            if single:
                chunks += chunk_single_release(pkg, single.group(1), text, md, f["source_url"])
            else:
                chunks += chunk_changelog(pkg, text, md, f["source_url"])
    return chunks


def main() -> None:
    store = Store.from_disk()
    chunks = [c for c in collect() if store.release(c.package, c.version) is not None]
    rows = []
    for n, c in enumerate(chunks):
        ids = set(c.advisory_ids)
        for i in c.advisory_ids:
            adv = store.advisory(c.package, i)
            if adv:
                ids |= {x.upper() for x in adv.ids}
        rel = store.release(c.package, c.version)
        rows.append({
            "chunk_id": f"{c.package}-{c.version}-{c.source_type}-{n}",
            "package": c.package, "version": c.version, "version_key": version_key(c.version),
            "is_prerelease": rel.version.is_prerelease, "release_date": rel.date or "",
            "source_type": c.source_type, "section": c.section, "text": c.text,
            # pipes on both ends so `LIKE '%|CVE-2024-1|%'` matches whole IDs only
            "advisory_ids": "|" + "|".join(sorted(ids)) + "|" if ids else "",
            "source_url": c.source_url,
        })
    print(f"{len(rows)} chunks; embedding...")
    vectors = embed_passages([r["text"] for r in rows])
    for r, v in zip(rows, vectors):
        r["vector"] = v
    if DB.exists():
        shutil.rmtree(DB)
    db = lancedb.connect(DB)
    table = db.create_table("chunks", rows)
    table.create_fts_index("text")
    by_pkg: dict[str, int] = {}
    for r in rows:
        by_pkg[r["package"]] = by_pkg.get(r["package"], 0) + 1
    print("indexed:", by_pkg, "| with advisory IDs:", sum(bool(r["advisory_ids"]) for r in rows))


if __name__ == "__main__":
    main()
