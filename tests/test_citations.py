"""The citation check: keys resolve only against what was retrieved, and report labels get their own lines."""

from agent.team import Run, apply_citations
from tools import search


def run_with_django_notes() -> Run:
    run = Run()
    for p in search.release_notes("django", "4.2.30")["passages"]:
        run.passages[p["chunk_id"]] = p
    return run


def test_prefixed_and_bare_keys_resolve_unknown_dropped():
    run = run_with_django_notes()
    cid = next(iter(run.passages))
    text = f"Fix A [S:{cid}]. Fix B [{cid}]. Advisory [GHSA-923m-gv2p-w5qp]. Made up [S:not-a-chunk]. Plain [note]."
    body, check = apply_citations(text, run)
    assert check["kept"] == 2  # the passage (counted once) and the advisory
    assert check["dropped"] == ["S:not-a-chunk"]
    assert cid not in body.split("**Sources**")[0]  # bare id became a numbered link
    assert "[note]" in body  # ordinary brackets untouched


def test_section_labels_start_new_paragraphs():
    run = Run()
    text = ("**Verdict:** affected by 9 advisories **What changes on the way**\n* one\n"
            "* two. **Check before upgrading:**\n* three\n**Can't tell from the data:** x")
    body, _ = apply_citations(text, run)
    for label in ("**What changes on the way**", "**Check before upgrading:**", "**Can't tell from the data:**"):
        assert f"\n\n{label}" in body
    assert "**What changes on the way**\n\n* one" in body
