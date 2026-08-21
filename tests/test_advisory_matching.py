"""
Advisory regression tests for specs/vulnerability_dependency_parser_spec.md.

Every case is a package that was previously reported as vulnerable only
because the parser had invented a version (0.0.0), which falls inside every
`< X` affected range.  With the real version extracted, none of them match.
"""

import pytest

from checkdeps import osv_affects, parse_requirements_txt, version_in_specifier


# id, requirement, advisory, affected range, expected verdict
ADVISORY_REGRESSIONS = [
    ("uvicorn[standard]==0.34.0", "GHSA-33c7-2mpw-hg34", "<0.11.7", False),
    ("uvicorn[standard]==0.34.0", "GHSA-f97h-2pfx-f59f", "<0.11.7", False),
    ("python-jose[cryptography]==3.4.0", "GHSA-6c5p-j8vq-pqhj", "<3.4.0", False),
    ("python-jose[cryptography]==3.4.0", "GHSA-cjwg-qfpm-7377", "<3.4.0", False),
    ("python-jose[cryptography]==3.4.0", "GHSA-w799-prg3-cx77", "<1.3.2", False),
]


def osv_record(advisory_id, package_name, introduced, fixed):
    """A minimal OSV record shaped like the real API response."""
    return {
        "id": advisory_id,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package_name},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": introduced}, {"fixed": fixed}],
                    }
                ],
            }
        ],
    }


@pytest.mark.parametrize(
    "requirement,advisory,affected_range,expected",
    ADVISORY_REGRESSIONS,
    ids=[r[1] for r in ADVISORY_REGRESSIONS],
)
def test_advisory_regression(tmp_path, requirement, advisory, affected_range, expected):
    path = tmp_path / "requirements.txt"
    path.write_text(requirement + "\n", encoding="utf-8")
    dep = parse_requirements_txt(path).dependencies[0]

    # The parser must supply a real version for the match to mean anything.
    assert dep.version is not None
    assert dep.version != "0.0.0"

    # PEP 440 comparison against the advisory range, not a string compare.
    assert version_in_specifier(dep.version, affected_range) is expected

    # And the same verdict through the OSV record shape the scanner receives.
    fixed = affected_range.lstrip("<")
    record = osv_record(advisory, dep.name, "0", fixed)
    assert osv_affects(record, dep.ecosystem, dep.name, dep.version) is expected


def test_fabricated_version_would_have_matched_everything():
    """Why these regressions exist: 0.0.0 is below every fixed version."""
    for _, _, affected_range, _ in ADVISORY_REGRESSIONS:
        assert version_in_specifier("0.0.0", affected_range) is True


def test_version_comparison_is_not_lexicographic():
    # "0.9.0" > "0.11.7" as strings, but not as PEP 440 versions.
    assert version_in_specifier("0.9.0", "<0.11.7") is True
    assert version_in_specifier("0.34.0", "<0.11.7") is False
    assert version_in_specifier("1.10.0", ">=1.9.0") is True


def test_osv_affects_inside_range():
    record = osv_record("GHSA-x", "uvicorn", "0", "0.11.7")
    assert osv_affects(record, "PyPI", "uvicorn", "0.11.6") is True
    assert osv_affects(record, "PyPI", "uvicorn", "0.11.7") is False


def test_osv_affects_uses_canonical_names():
    record = osv_record("GHSA-x", "python_jose", "0", "3.4.0")
    assert osv_affects(record, "PyPI", "python-jose", "3.3.0") is True
    assert osv_affects(record, "PyPI", "python-jose", "3.4.0") is False


def test_osv_affects_last_affected_event():
    record = {
        "id": "GHSA-x",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0"}, {"last_affected": "1.5"}],
                    }
                ],
            }
        ],
    }
    assert osv_affects(record, "PyPI", "pkg", "0.9") is False
    assert osv_affects(record, "PyPI", "pkg", "1.5") is True
    assert osv_affects(record, "PyPI", "pkg", "1.6") is False


def test_osv_affects_explicit_version_list():
    record = {
        "id": "GHSA-x",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "versions": ["1.0", "1.1"],
            }
        ],
    }
    assert osv_affects(record, "PyPI", "pkg", "1.1") is True
    assert osv_affects(record, "PyPI", "pkg", "1.2") is False


def test_osv_affects_is_indeterminate_when_it_cannot_decide():
    # A GIT range cannot be evaluated with PEP 440, so the API verdict stands.
    git_range = {
        "id": "GHSA-x",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    assert osv_affects(git_range, "PyPI", "pkg", "1.0") is None

    # A record that never names the package cannot be second-guessed either.
    other = osv_record("GHSA-x", "somethingelse", "0", "2.0")
    assert osv_affects(other, "PyPI", "pkg", "1.0") is None

    # Non-PyPI ecosystems are left to the API.
    assert osv_affects(osv_record("GHSA-x", "pkg", "0", "2.0"), "npm", "pkg", "1.0") is None


def test_unresolved_dependency_is_never_queried(tmp_path, monkeypatch):
    import checkdeps

    path = tmp_path / "requirements.txt"
    path.write_text("requests\nfastapi>=0.115,<1\n", encoding="utf-8")
    report = parse_requirements_txt(path)
    assert all(d.version is None for d in report.dependencies)

    def fail(*args, **kwargs):
        raise AssertionError("OSV must not be queried for unresolved versions")

    monkeypatch.setattr(checkdeps.requests, "Session", fail)
    monkeypatch.setattr(checkdeps, "_load_cache", lambda: {})

    results = checkdeps.query_osv(report.dependencies)
    assert results == {0: [], 1: []}
