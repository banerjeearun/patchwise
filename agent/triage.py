"""Code-side triage, run before the Lead: what did the user give us, and what do the facts say?

The Lead then plans from this table instead of guessing which pins are affected.
"""

from __future__ import annotations

import re

from tools.chunking import ADVISORY_ID
from tools.packages import PACKAGES
from tools.versions import is_affected, minimal_safe_version, parse, store

ALIASES = {"pil": "pillow", "python-pillow": "pillow", "django-framework": "django"}
REQ = re.compile(r"(?<![\w.\-])([A-Za-z][\w.\-]*)(\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)\s*([0-9][\w.\-*]*)")


def norm(name: str) -> str:
    n = name.lower().replace("_", "-")
    return ALIASES.get(n, n)


def triage(text: str) -> dict:
    s = store()
    seen: set[str] = set()
    pins, unpinned, not_covered = [], [], []
    for m in REQ.finditer(text):
        pkg, op, ver = norm(m.group(1)), m.group(3), m.group(4).rstrip(".,;")
        if pkg in seen:
            continue
        seen.add(pkg)
        if pkg not in PACKAGES:
            not_covered.append(f"{pkg}{op}{ver}")
        elif op not in ("==", "===") or "*" in ver:
            unpinned.append({"package": pkg, "spec": f"{op}{ver}",
                             "why": "not an exact pin, so the installed version is unknown"})
        elif s.release(pkg, ver) is None:
            unpinned.append({"package": pkg, "spec": f"=={ver}",
                             "why": f"{ver} is not a {pkg} release on PyPI in this snapshot"})
        else:
            pins.append((pkg, ver))
    lowered = text.lower()
    mentioned = [p for p in PACKAGES if p not in seen and re.search(rf"\b{p}\b", lowered)]
    if "pil" in re.findall(r"\b\w+\b", lowered) and "pillow" not in seen and "pillow" not in mentioned:
        mentioned.append("pillow")

    ids = sorted({i.upper() for i in ADVISORY_ID.findall(text)})
    advisories = []
    for i in ids:
        found = s.find_advisory(i)
        advisories.append({"id": i, "packages": sorted({a.package for a in found}),
                           "in_snapshot": bool(found)})

    checked = []
    for pkg, ver in pins:
        r = minimal_safe_version(pkg, ver)
        row = {
            "package": pkg, "pinned": ver, "line": r["pinned_line"],
            "advisories_affecting_pin": len(r["affecting_pinned"]),
            "full_fix_on_same_line": r["same_line"]["version"] if r["same_line"] else None,
            "best_partial_on_line": ({k: r["same_line_best_partial"][k] for k in ("version", "cleared")}
                                     | {"remaining": len(r["same_line_best_partial"]["remaining"]),
                                        "newly_introduced": len(r["same_line_best_partial"]["newly_introduced"])}
                                     if r["same_line_best_partial"] else None),
            "smallest_full_fix": ({"version": r["overall"]["version"], "jump": r["overall"]["jump"]}
                                  if r["overall"] else None),
            "unfixable": [a["id"] for a in r["unfixable"]],
        }
        asked = [a for a in advisories if pkg in a["packages"]]
        if asked:
            row["asked_advisories"] = [{"id": a["id"], "affected": is_affected(pkg, ver, a["id"]).get("affected")}
                                       for a in asked]
        checked.append(row)

    return {
        "checked_pins": checked,
        "unpinned_or_unknown": unpinned,
        "not_covered": not_covered,
        "mentioned_without_version": mentioned,
        "advisory_ids": advisories,
        "covered_packages": list(PACKAGES),
    }
