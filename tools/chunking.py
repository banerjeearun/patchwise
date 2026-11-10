"""Split changelogs into chunks that never mix two releases.

Step 1: find the version headings and cut the file into one section per release.
Step 2: inside a release, cut at sub-headings ("Security", "Bug fixes", one per CVE in Django),
        then pack paragraphs up to MAX_CHARS so each chunk fits the embedding model.
Every chunk is prefixed with "<package> <version> - <section>" (a contextual header), so a chunk
that just says "Fixed a bug in decompression" still embeds as being about urllib3 2.5.0.
Line numbers are kept so citations link to the exact lines (?plain=1#L10-L24).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_CHARS = 1800

RST_UNDER = re.compile(r"^([=\-~^*#\"+`])\1{2,}\s*$")
MD_HEAD = re.compile(r"^(#{1,4})\s+(.+?)\s*#*\s*$")
VERSION = re.compile(r"^\s*(?:Django\s+|Pillow\s+)?v?(\d+(?:\.\d+){1,3}(?:(?:a|b|rc)\d+)?)(?=[\s(:\-]|$)")
CVE_ROLE = re.compile(r":cve:`(\d{4}-\d{4,})`")  # Pillow's Sphinx role
ADVISORY_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[2-9cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+)\b", re.I)


@dataclass
class Chunk:
    package: str
    version: str
    section: str
    text: str
    start_line: int  # 1-based, inclusive
    end_line: int
    source_type: str
    source_url: str
    advisory_ids: list[str] = field(default_factory=list)


def headings(lines: list[str], md: bool) -> list[tuple[int, int, str, str]]:
    """(line index of title, index where the body starts, title, level marker)."""
    out = []
    for i, line in enumerate(lines):
        if md:
            m = MD_HEAD.match(line)
            if m:
                out.append((i, i + 1, m.group(2).strip(), m.group(1)))
        elif i + 1 < len(lines):
            title, under = line.strip(), lines[i + 1].rstrip()
            if title and not RST_UNDER.match(line.rstrip()) and RST_UNDER.match(under) \
                    and len(under.strip()) >= max(3, len(title) - 2) and not title.startswith(".."):
                out.append((i, i + 2, title, under.strip()[0]))
    return out


def version_sections(lines: list[str], md: bool) -> list[tuple[str, int, int]]:
    """(version, start index, end index) for each release in a multi-release changelog.
    The version-heading level is the level of the first heading that names a version."""
    hs = [(i, b, t, lvl) for i, b, t, lvl in headings(lines, md) if VERSION.match(t)]
    if not hs:
        return []
    level = hs[0][3]
    hs = [h for h in hs if h[3] == level]
    out = []
    for n, (i, _, title, _) in enumerate(hs):
        end = hs[n + 1][0] if n + 1 < len(hs) else len(lines)
        # rst overline style: drop the overline that belongs to the next heading
        if end < len(lines) and end > 0 and RST_UNDER.match(lines[end - 1].rstrip() or "x"):
            end -= 1
        out.append((VERSION.match(title).group(1), i, end))
    return out


def chunk_release(package: str, version: str, lines: list[str], start: int, end: int, md: bool,
                  source_type: str, source_url: str, permalink_lines: bool = True) -> list[Chunk]:
    """Cut one release's lines [start, end) at sub-headings, then pack paragraphs."""
    body = lines[start:end]
    subs = [(i, b, t) for i, b, t, _ in headings(body, md) if not VERSION.match(t) or i > 1]
    cuts = [(0, 0, "")] + subs  # leading text (before the first sub-heading) gets no section name
    chunks: list[Chunk] = []
    for n, (i, b, title) in enumerate(cuts):
        stop = cuts[n + 1][0] if n + 1 < len(cuts) else len(body)
        lo = b if n else 0
        # paragraphs, with their absolute line numbers
        paras, cur, cur_start = [], [], None
        for j in range(lo, stop):
            text = body[j]
            if RST_UNDER.match(text.rstrip() or "x") and not text.strip("=-~^*#\"+` \n"):
                continue
            if text.strip():
                if cur_start is None:
                    cur_start = start + j
                cur.append(text.rstrip())
            elif cur:
                paras.append((cur_start, start + j - 1, "\n".join(cur)))
                cur, cur_start = [], None
        if cur:
            paras.append((cur_start, start + stop - 1, "\n".join(cur)))
        section = title if n else ""
        buf, b_start, b_end = [], None, None
        for p_start, p_end, p in _split_long(paras):
            if buf and sum(len(x) for x in buf) + len(p) > MAX_CHARS:
                chunks.append(_make(package, version, section, buf, b_start, b_end, source_type, source_url, permalink_lines))
                buf, b_start = [], None
            if b_start is None:
                b_start = p_start
            buf.append(p)
            b_end = p_end
        if buf:
            chunks.append(_make(package, version, section, buf, b_start, b_end, source_type, source_url, permalink_lines))
    return [c for c in chunks if len(c.text.split("\n", 1)[-1].strip()) > 20]


def _split_long(paras: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """A paragraph over MAX_CHARS (usually a bullet list with no blank lines) is cut at line
    boundaries, so no chunk is silently truncated by the embedding model."""
    out = []
    for a, b, p in paras:
        if len(p) <= MAX_CHARS:
            out.append((a, b, p))
            continue
        cur, cur_a = [], a
        for k, line in enumerate(p.split("\n")):
            if cur and sum(len(x) + 1 for x in cur) + len(line) > MAX_CHARS:
                out.append((cur_a, a + k - 1, "\n".join(cur)))
                cur, cur_a = [], a + k
            cur.append(line[:MAX_CHARS])
        if cur:
            out.append((cur_a, b, "\n".join(cur)))
    return out


def _make(package, version, section, buf, a, b, source_type, url, permalink_lines) -> Chunk:
    header = f"{package} {version}" + (f" - {section}" if section else "")
    text = header + "\n" + "\n\n".join(buf)
    ids = sorted({m.upper() for m in ADVISORY_ID.findall(text)} | {f"CVE-{m}" for m in CVE_ROLE.findall(text)})
    link = f"{url}?plain=1#L{a + 1}-L{b + 1}" if permalink_lines else url
    return Chunk(package, version, section, text, a + 1, b + 1, source_type, link, ids)


def chunk_changelog(package: str, text: str, md: bool, source_url: str) -> list[Chunk]:
    lines = text.splitlines()
    out = []
    for version, s, e in version_sections(lines, md):
        out += chunk_release(package, version, lines, s, e, md, "changelog", source_url)
    return out


def chunk_single_release(package: str, version: str, text: str, md: bool, source_url: str,
                         permalink_lines: bool = True) -> list[Chunk]:
    lines = text.splitlines()
    return chunk_release(package, version, lines, 0, len(lines), md, "release_note", source_url, permalink_lines)
