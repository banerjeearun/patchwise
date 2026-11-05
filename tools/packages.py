"""The packages PatchWise covers, and where each one's data lives. One place to change."""

# line: how a "release line" is defined for backports and "same-line" upgrades.
#   minor -> 4.2.x is one line (Django feature releases, Starlette 0.x/1.x minors can break)
#   major -> 2.x is one line (projects that follow semver and rarely backport)
# changelog: files fetched from the repo at a pinned commit. A trailing "/" means a directory.
PACKAGES = {
    "django": {
        "repo": "django/django",
        "line": "minor",
        "changelog": ["docs/releases/"],
        "min_version": "3.2",  # skip release notes for versions older than this
    },
    "urllib3": {"repo": "urllib3/urllib3", "line": "major", "changelog": ["CHANGES.rst"]},
    "pillow": {
        "repo": "python-pillow/Pillow",
        "line": "major",
        # CHANGES.rst stops at 11.0; newer notes are per-version files plus GitHub Releases
        "changelog": ["CHANGES.rst", "docs/releasenotes/"],
        "github_releases": True,
        "min_version": "9.0",
    },
    "aiohttp": {"repo": "aio-libs/aiohttp", "line": "minor", "changelog": ["CHANGES.rst"]},
    "starlette": {"repo": "Kludex/starlette", "line": "minor", "changelog": ["docs/release-notes.md"]},
    "cryptography": {"repo": "pyca/cryptography", "line": "major", "changelog": ["CHANGELOG.rst"]},
}
