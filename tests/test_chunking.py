from tools.chunking import MAX_CHARS, chunk_changelog, chunk_single_release

RST = """\
Changelog
=========

2.1.0 (2026-01-02)
==================

Security
--------

- Fixed CVE-2026-0001 in the parser.

Features
--------

- Added a thing.

2.0.1 (2025-12-01)
==================

- Fixed a bug. See https://github.com/advisories/ghsa-2xpw-w6gg-jr37 for details.
"""

MD = """\
## 1.10.0 (October 24, 2026)

#### Changed

* Compare multidicts by key.

## 1.9.0 (October 1, 2026)

* Something else that is long enough.
"""

DJANGO = """\
===========================
Django 4.2.10 release notes
===========================

*February 6, 2024*

Django 4.2.10 fixes a security issue with severity "moderate" in 4.2.9.

CVE-2024-24680: Potential denial-of-service in ``intcomma`` template filter
===========================================================================

The ``intcomma`` template filter was subject to a potential denial-of-service.
"""


def test_rst_one_release_per_chunk_and_sections():
    cs = chunk_changelog("demo", RST, md=False, source_url="https://x/CHANGES.rst")
    assert {c.version for c in cs} == {"2.1.0", "2.0.1"}
    sec = [c for c in cs if c.section == "Security"][0]
    assert sec.version == "2.1.0" and "2.0.1" not in sec.text
    assert sec.advisory_ids == ["CVE-2026-0001"]
    assert sec.text.startswith("demo 2.1.0 - Security")  # contextual header
    assert sec.source_url.startswith("https://x/CHANGES.rst?plain=1#L")


def test_lowercase_ghsa_is_normalized():
    cs = chunk_changelog("demo", RST, md=False, source_url="u")
    assert [c.advisory_ids for c in cs if c.version == "2.0.1"] == [["GHSA-2XPW-W6GG-JR37"]]


def test_markdown_versions():
    cs = chunk_changelog("demo", MD, md=True, source_url="u")
    assert {c.version for c in cs} == {"1.10.0", "1.9.0"}
    assert any(c.section == "Changed" for c in cs)


def test_django_single_release_cve_section():
    cs = chunk_single_release("django", "4.2.10", DJANGO, md=False, source_url="u")
    cve = [c for c in cs if c.advisory_ids]
    assert len(cve) == 1 and cve[0].section.startswith("CVE-2024-24680")


def test_long_lists_are_split_under_limit():
    bullets = "\n".join(f"- item {i} " + "x" * 80 for i in range(60))
    text = f"3.0.0 (2026-01-01)\n==================\n\n{bullets}\n"
    cs = chunk_changelog("demo", text, md=False, source_url="u")
    assert len(cs) > 1 and all(len(c.text) <= MAX_CHARS + 100 for c in cs)


def test_release_page_links_have_no_line_anchor():
    cs = chunk_single_release("demo", "1.0.0", "## Changes\n\n* A change long enough to keep.", md=True,
                              source_url="https://github.com/o/r/releases/tag/1.0.0", permalink_lines=False)
    assert cs[0].source_url == "https://github.com/o/r/releases/tag/1.0.0"
