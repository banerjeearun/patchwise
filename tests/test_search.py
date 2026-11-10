"""Against the real index (data/lancedb). Needs the embedding model, downloaded on first run."""

from tools.search import notes_for_advisory, release_notes, search_docs


def test_m3_demo_query_finds_fix_in_top3():
    r = search_docs("request body not removed when redirect changes method to GET",
                    "urllib3", after_version="1.26.17", up_to_version="2.0.7")
    assert "1.26.18" in [p["version"] for p in r["passages"][:3]]


def test_filters_respect_package_and_range():
    r = search_docs("security fix", "aiohttp", after_version="3.9.0", up_to_version="3.9.5", k=10)
    assert r["passages"] and all(p["package"] == "aiohttp" for p in r["passages"])
    assert all(p["version"] in {"3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5"} for p in r["passages"])


def test_notes_for_advisory_finds_unnamed_fix():
    r = notes_for_advisory("urllib3", "CVE-2023-45803")
    assert r["fix_versions"] == ["1.26.18", "2.0.7"]
    assert {p["version"] for p in r["at_fix_releases"]} >= {"1.26.18", "2.0.7"}


def test_notes_for_advisory_by_name_across_lines():
    r = notes_for_advisory("django", "CVE-2024-24680")
    assert {"3.2.24", "4.2.10", "5.0.2"} <= {p["version"] for p in r["naming_the_advisory"]}


def test_release_notes_exact():
    assert release_notes("django", "4.2.10")["count"] >= 1


def test_errors_not_exceptions():
    assert "error" in search_docs("x", "flask")
    assert "error" in search_docs("x", "django", after_version="banana")
    assert "error" in notes_for_advisory("django", "CVE-1999-0000")
