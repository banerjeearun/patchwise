import pytest

from tools.versions import Store, fixes_by_branch, is_affected, minimal_safe_version, advisories_for

PKGS = {"demo": {"line": "minor"}, "semver": {"line": "major"}}


def rel(pkg, *versions, yanked=(), nofiles=()):
    return [{"package": pkg, "version": v, "yanked": v in yanked, "has_files": v not in nofiles} for v in versions]


DEMO_RELEASES = rel("demo", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.1.0", "1.1.1", "1.2.0", "1.2.1",
                    "2.0.0rc1", "2.0.0", "2.0.1", yanked={"1.0.2"})

# A1: backported to 1.0 and 1.1, never fixed on 1.2 (it went straight to 2.0.0)
A1 = {"package": "demo", "id": "GHSA-aaaa", "ids": ["GHSA-aaaa", "CVE-2025-0001"], "ranges": [
    {"source": "GHSA-aaaa", "events": [{"introduced": "0"}, {"fixed": "1.0.2"},
                                       {"introduced": "1.1.0"}, {"fixed": "1.1.1"},
                                       {"introduced": "1.2.0"}, {"fixed": "2.0.0"}]}]}
# A2: last_affected, introduced mid-line
A2 = {"package": "demo", "id": "GHSA-bbbb", "ids": ["GHSA-bbbb"], "ranges": [
    {"source": "GHSA-bbbb", "events": [{"introduced": "1.0.1"}, {"last_affected": "1.0.2"}]}]}
# A3: no fix at all
A3 = {"package": "demo", "id": "GHSA-cccc", "ids": ["GHSA-cccc"], "ranges": [
    {"source": "GHSA-cccc", "events": [{"introduced": "2.0.1"}]}]}


@pytest.fixture
def s():
    return Store(DEMO_RELEASES, [A1, A2, A3], packages=PKGS)


def test_just_before_fix_is_affected(s):
    assert is_affected("demo", "1.0.1", "GHSA-aaaa", s)["affected"] is True


def test_fix_itself_is_not_affected(s):
    assert is_affected("demo", "1.1.1", "GHSA-aaaa", s)["affected"] is False


def test_lookup_by_cve_alias_and_case(s):
    assert is_affected("demo", "1.0.0", "cve-2025-0001", s)["affected"] is True


def test_outside_every_range(s):
    assert is_affected("demo", "2.0.1", "GHSA-aaaa", s)["affected"] is False
    assert is_affected("demo", "1.0.0", "GHSA-bbbb", s)["affected"] is False


def test_last_affected_is_inclusive(s):
    assert is_affected("demo", "1.0.2", "GHSA-bbbb", s)["affected"] is True
    assert is_affected("demo", "1.0.3", "GHSA-bbbb", s)["affected"] is False


def test_prerelease_ordering(s):
    # 2.0.0rc1 < 2.0.0, so it is still inside [1.2.0, 2.0.0)
    assert is_affected("demo", "2.0.0rc1", "GHSA-aaaa", s)["affected"] is True


def test_fixes_by_branch_skips_yanked_and_reports_missing_backport(s):
    lines = fixes_by_branch("demo", "GHSA-aaaa", s)["lines"]
    assert lines["1.0"]["earliest_fix"] == "1.0.3"  # 1.0.2 is the stated fix but it's yanked
    assert lines["1.1"]["earliest_fix"] == "1.1.1"
    assert lines["1.2"]["earliest_fix"] is None     # no backport on 1.2
    assert "2.0" in lines  # 2.0.0rc1 is affected; 2.0.0 fixes it
    assert lines["2.0"]["earliest_fix"] == "2.0.0"


def test_minimal_safe_clears_all_advisories(s):
    r = minimal_safe_version("demo", "1.0.1", s)
    # 1.0.2 yanked; 1.0.3 clears A1 (fixed 1.0.2) and A2 (last_affected 1.0.2)
    assert r["same_line"]["version"] == "1.0.3"
    assert r["same_line"]["jump"] == "patch"
    assert {a["id"] for a in r["affecting_pinned"]} == {"GHSA-aaaa", "GHSA-bbbb"}


def test_minimal_safe_no_same_line_fix(s):
    r = minimal_safe_version("demo", "1.2.0", s)
    assert r["same_line"] is None
    assert r["overall"]["version"] == "2.0.0"
    assert r["overall"]["jump"] == "major"


def test_partial_best_on_line_when_no_full_fix(s):
    # 1.2.x can't clear A1 (no backport), so nothing on 1.2 helps: no partial answer.
    assert minimal_safe_version("demo", "1.2.0", s)["same_line_best_partial"] is None
    # On 1.0, 1.0.3 clears both A1 and A2 fully -> same_line, and no partial needed.
    r = minimal_safe_version("demo", "1.0.0", s)
    assert r["same_line"]["version"] == "1.0.3" and r["same_line_best_partial"] is None


def test_partial_reports_newly_introduced_and_skips_useless():
    rels = rel("demo", "1.0.0", "1.0.1", "1.0.2", "2.0.0")
    old = {"package": "demo", "id": "GHSA-old", "ranges": [
        {"source": "GHSA-old", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}, {"introduced": "1.0.2"}, {"fixed": "2.0.0"}]}]}
    new = {"package": "demo", "id": "GHSA-new", "ranges": [
        {"source": "GHSA-new", "events": [{"introduced": "1.0.1"}, {"fixed": "2.0.0"}]}]}
    st = Store(rels, [old, new], packages=PKGS)
    best = minimal_safe_version("demo", "1.0.0", st)["same_line_best_partial"]
    assert best["version"] == "1.0.1" and best["cleared"] == 1
    assert [a["id"] for a in best["newly_introduced"]] == ["GHSA-new"]
    # from 1.0.1, nothing on 1.0 clears GHSA-new -> no partial answer
    assert minimal_safe_version("demo", "1.0.1", st)["same_line_best_partial"] is None


def test_ghsa_basis_ignores_broad_pysec_range():
    # GHSA knows about the 1.0.3 backport; PYSEC says "everything below 2.0.0" (stored as alt_ranges).
    adv = {"package": "demo", "id": "GHSA-dddd", "ids": ["GHSA-dddd", "PYSEC-1"], "basis": "ghsa",
           "ranges": [{"source": "GHSA-dddd", "events": [{"introduced": "0"}, {"fixed": "1.0.3"},
                                                         {"introduced": "1.1.0"}, {"fixed": "2.0.0"}]}],
           "alt_ranges": [{"source": "PYSEC-1", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
    st = Store(DEMO_RELEASES, [adv], packages=PKGS)
    assert is_affected("demo", "1.0.3", "PYSEC-1", st)["affected"] is False


def test_unfixable_is_reported_not_hidden(s):
    r = minimal_safe_version("demo", "2.0.1", s)
    assert [a["id"] for a in r["unfixable"]] == ["GHSA-cccc"]
    assert r["same_line"]["version"] == "2.0.1"  # nothing fixable affects it


def test_unknown_inputs_return_errors(s):
    assert "error" in is_affected("nope", "1.0", "GHSA-aaaa", s)
    assert "error" in is_affected("demo", "9.9.9", "GHSA-aaaa", s)
    assert "error" in is_affected("demo", "1.0.0", "GHSA-zzzz", s)
    assert "error" in minimal_safe_version("demo", "not-a-version", s)


def test_advisories_for(s):
    assert advisories_for("demo", "1.0.1", s)["count"] == 2


# --- against the real snapshot (frozen, so these are stable) ---

@pytest.fixture(scope="module")
def real():
    return Store.from_disk()


def test_real_urllib3_cve_2023_45803(real):
    assert is_affected("urllib3", "1.26.17", "CVE-2023-45803", real)["affected"] is True
    assert is_affected("urllib3", "1.26.18", "CVE-2023-45803", real)["affected"] is False
    lines = fixes_by_branch("urllib3", "CVE-2023-45803", real)["lines"]
    assert lines["1"]["earliest_fix"] == "1.26.18"
    assert lines["2"]["earliest_fix"] == "2.0.7"


def test_real_every_advisory_resolves(real):
    for pkg, advs in real.advisories.items():
        for a in advs:
            assert "error" not in fixes_by_branch(pkg, a.id, real)
