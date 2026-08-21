"""
Acceptance tests for specs/vulnerability_dependency_parser_spec.md.

Each test below carries the `id` of the acceptance test it implements.
"""

import pytest

from checkdeps import (
    ParseReport,
    VersionResolver,
    exact_pin,
    parse_requirements_txt,
)


def write_requirements(tmp_path, contents, name="requirements.txt"):
    path = tmp_path / name
    path.write_text(contents, encoding="utf-8")
    return path


def parse_one(tmp_path, line, environment=None, resolver=None):
    """Parse a single requirement line and return its dependency record."""
    report = parse_requirements_txt(
        write_requirements(tmp_path, line + "\n"),
        environment=environment,
        resolver=resolver,
    )
    records = report.dependencies + report.inactive
    assert len(records) == 1, f"expected one record, got {records}"
    return records[0], report


# ---------------------------------------------------------------------------
# acceptance_tests
# ---------------------------------------------------------------------------


def test_extra_and_exact_pin(tmp_path):
    """id: extra_and_exact_pin"""
    dep, _ = parse_one(tmp_path, "uvicorn[standard]==0.34.0")
    assert dep.name == "uvicorn"
    assert list(dep.extras) == ["standard"]
    assert dep.specifier == "==0.34.0"
    assert dep.version == "0.34.0"


def test_hyphenated_name_extra_and_exact_pin(tmp_path):
    """id: hyphenated_name_extra_and_exact_pin"""
    dep, _ = parse_one(tmp_path, "python-jose[cryptography]==3.4.0")
    assert dep.name == "python-jose"
    assert list(dep.extras) == ["cryptography"]
    assert dep.specifier == "==3.4.0"
    assert dep.version == "3.4.0"


def test_another_extra_regression(tmp_path):
    """id: another_extra_regression"""
    dep, _ = parse_one(tmp_path, "psycopg[binary]==3.2.3")
    assert dep.name == "psycopg"
    assert list(dep.extras) == ["binary"]
    assert dep.specifier == "==3.2.3"
    assert dep.version == "3.2.3"


def test_multiple_extras_and_marker(tmp_path):
    """id: multiple_extras_and_marker"""
    dep, _ = parse_one(
        tmp_path,
        'example_pkg[foo,bar]==1.2.3; python_version >= "3.11"',
        environment={"python_version": "3.11"},
    )
    assert dep.name == "example-pkg"
    assert list(dep.extras) == ["bar", "foo"]
    assert dep.specifier == "==1.2.3"
    assert dep.version == "1.2.3"
    assert dep.active is True


def test_inactive_marker(tmp_path):
    """id: inactive_marker"""
    dep, report = parse_one(
        tmp_path,
        'colorama==0.4.6; sys_platform == "win32"',
        environment={"sys_platform": "linux"},
    )
    assert dep.name == "colorama"
    assert dep.active is False
    assert dep.vulnerability_match == "skipped"
    # An inactive requirement is not offered to the matching stage.
    assert report.dependencies == []
    assert report.inactive == [dep]


def test_ranged_requirement_is_not_a_resolved_version(tmp_path):
    """id: ranged_requirement_is_not_a_resolved_version"""
    dep, _ = parse_one(tmp_path, "fastapi>=0.115,<1")
    assert dep.name == "fastapi"
    assert list(dep.extras) == []
    assert dep.specifier == "<1,>=0.115"
    assert dep.version is None
    assert dep.vulnerability_match == "indeterminate"


def test_unpinned_requirement_is_not_zero(tmp_path):
    """id: unpinned_requirement_is_not_zero"""
    dep, _ = parse_one(tmp_path, "requests")
    assert dep.name == "requests"
    assert list(dep.extras) == []
    assert dep.specifier == ""
    assert dep.version is None
    assert dep.vulnerability_match == "indeterminate"


def test_invalid_requirement(tmp_path):
    """id: invalid_requirement"""
    report = parse_requirements_txt(
        write_requirements(tmp_path, "uvicorn[standard]==\n")
    )
    assert report.dependencies == []
    assert report.inactive == []
    assert len(report.errors) == 1
    issue = report.errors[0]
    assert issue.kind == "parse_error"
    assert issue.severity == "error"
    assert issue.vulnerability_match == "not_attempted"
    assert issue.line == 1


# ---------------------------------------------------------------------------
# invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "fastapi>=0.115,<1",
        "fastapi==1.2.*",
        "fastapi~=1.2.3",
        "fastapi!=1.0",
        "fastapi>=1.0,!=1.2",
        "fastapi",
        "fastapi @ https://example.invalid/fastapi.git@main",
    ],
)
def test_no_fabricated_version(tmp_path, line):
    """No range, wildcard, compatible release, exclusion or URL invents a version."""
    dep, _ = parse_one(tmp_path, line)
    assert dep.version is None
    assert dep.vulnerability_match == "indeterminate"


def test_forbidden_fallback_never_appears(tmp_path):
    contents = "\n".join(
        [
            "requests",
            "fastapi>=0.115,<1",
            "uvicorn[standard]==0.34.0",
            "flask~=3.0",
        ]
    )
    report = parse_requirements_txt(write_requirements(tmp_path, contents + "\n"))
    versions = [d.version for d in report.dependencies]
    assert "0.0.0" not in versions
    assert versions.count(None) == 3
    assert "0.34.0" in versions


def test_extras_do_not_alter_name_or_version(tmp_path):
    plain, _ = parse_one(tmp_path, "psycopg==3.2.3")
    with_extras, _ = parse_one(tmp_path, "psycopg[binary,pool]==3.2.3")
    assert with_extras.name == plain.name
    assert with_extras.version == plain.version
    assert with_extras.specifier == plain.specifier
    assert list(with_extras.extras) == ["binary", "pool"]


def test_pep503_canonicalisation(tmp_path):
    dep, _ = parse_one(tmp_path, "Zope..Interface_Test--Pkg==5.0")
    assert dep.name == "zope-interface-test-pkg"


def test_triple_equals_is_an_exact_pin(tmp_path):
    dep, _ = parse_one(tmp_path, "pkg===1.2.3")
    assert dep.version == "1.2.3"


def test_triple_equals_non_pep440_is_unresolved(tmp_path):
    dep, _ = parse_one(tmp_path, "pkg===not-a-version")
    assert dep.version is None


def test_exact_pin_helper():
    assert exact_pin("==1.2.3") == "1.2.3"
    assert exact_pin("===1.2.3") == "1.2.3"
    assert exact_pin("==1.2.*") is None
    assert exact_pin("~=1.2.3") is None
    assert exact_pin(">=1.0,<2") is None
    assert exact_pin("") is None
    assert exact_pin(None) is None
    assert exact_pin("not a specifier") is None


# ---------------------------------------------------------------------------
# parsing_flow
# ---------------------------------------------------------------------------


def test_blank_lines_and_comments_ignored(tmp_path):
    contents = "\n".join(
        [
            "# a full-line comment",
            "",
            "   ",
            "requests==2.32.3  # trailing comment",
            "# another",
        ]
    )
    report = parse_requirements_txt(write_requirements(tmp_path, contents + "\n"))
    assert len(report.dependencies) == 1
    assert report.dependencies[0].version == "2.32.3"


def test_backslash_continuation_is_joined(tmp_path):
    contents = "uvicorn[standard]==\\\n0.34.0\n"
    report = parse_requirements_txt(write_requirements(tmp_path, contents))
    assert report.errors == []
    assert report.dependencies[0].name == "uvicorn"
    assert report.dependencies[0].version == "0.34.0"
    assert report.dependencies[0].line == 1


def test_hash_options_are_removed(tmp_path):
    contents = (
        "requests==2.32.3 \\\n"
        "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\\n"
        "    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
    )
    report = parse_requirements_txt(write_requirements(tmp_path, contents))
    assert report.errors == []
    assert report.dependencies[0].name == "requests"
    assert report.dependencies[0].version == "2.32.3"


def test_source_location_is_recorded(tmp_path):
    contents = "# comment\n\nrequests==2.32.3\n"
    path = write_requirements(tmp_path, contents)
    report = parse_requirements_txt(path)
    dep = report.dependencies[0]
    assert dep.source_file == str(path)
    assert dep.line == 3
    assert dep.location.endswith("requirements.txt:3")


def test_include_directive_is_followed(tmp_path):
    (tmp_path / "base.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    path = write_requirements(tmp_path, "-r base.txt\nflask==3.0.3\n")
    report = parse_requirements_txt(path)
    by_name = {d.name: d for d in report.dependencies}
    assert by_name["requests"].version == "2.32.3"
    assert by_name["requests"].source_file == str(tmp_path / "base.txt")
    assert by_name["requests"].line == 1
    assert by_name["flask"].source_file == str(path)


def test_include_cycle_is_detected(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("-r b.txt\nrequests==2.32.3\n", encoding="utf-8")
    b.write_text("-r a.txt\nflask==3.0.3\n", encoding="utf-8")
    report = parse_requirements_txt(a)
    assert {d.name for d in report.dependencies} == {"requests", "flask"}
    assert any(i.kind == "include_cycle" for i in report.issues)


def test_constraint_file_pins_but_is_not_a_dependency(tmp_path):
    (tmp_path / "constraints.txt").write_text("urllib3==2.2.2\n", encoding="utf-8")
    path = write_requirements(tmp_path, "-c constraints.txt\nurllib3\n")
    report = parse_requirements_txt(path)
    assert len(report.dependencies) == 1
    dep = report.dependencies[0]
    assert dep.name == "urllib3"
    assert dep.version == "2.2.2"
    assert dep.resolution == "constraint"
    assert dep.specifier == ""  # the requirement itself is still unpinned


def test_global_options_are_ignored(tmp_path):
    contents = (
        "--index-url https://example.invalid/simple\n"
        "--extra-index-url=https://other.invalid/simple\n"
        "-f https://example.invalid/wheels\n"
        "--no-index\n"
        "requests==2.32.3\n"
    )
    report = parse_requirements_txt(write_requirements(tmp_path, contents))
    assert [d.name for d in report.dependencies] == ["requests"]
    assert report.errors == []


def test_environment_evidence_beats_the_pin(tmp_path):
    resolver = VersionResolver(environment_versions={"Requests": "2.31.0"})
    dep, _ = parse_one(tmp_path, "requests==2.32.3", resolver=resolver)
    assert dep.version == "2.31.0"
    assert dep.resolution == "environment"


def test_direct_url_wheel_resolves_its_version(tmp_path):
    dep, _ = parse_one(
        tmp_path,
        "requests @ https://example.invalid/requests-2.32.3-py3-none-any.whl",
    )
    assert dep.name == "requests"
    assert dep.version == "2.32.3"
    assert dep.resolution == "artifact-url"
    assert dep.direct_url.endswith(".whl")


def test_direct_url_vcs_ref_stays_unresolved(tmp_path):
    dep, _ = parse_one(
        tmp_path, "requests @ git+https://example.invalid/requests.git@v2.32.3"
    )
    assert dep.version is None
    assert dep.vulnerability_match == "indeterminate"


def test_editable_without_egg_is_not_a_dependency(tmp_path):
    report = parse_requirements_txt(write_requirements(tmp_path, "-e .\n"))
    assert report.dependencies == []
    assert report.errors == []


def test_missing_include_is_a_parse_error(tmp_path):
    report = parse_requirements_txt(write_requirements(tmp_path, "-r missing.txt\n"))
    assert report.dependencies == []
    assert len(report.errors) == 1
    assert report.errors[0].kind == "parse_error"


def test_undecidable_marker_keeps_the_requirement(tmp_path):
    dep, report = parse_one(tmp_path, 'requests==2.32.3; extra == "socks"')
    assert dep.active is True
    assert dep.version == "2.32.3"
    assert any(i.kind == "marker_undecidable" for i in report.issues)


def test_report_helpers(tmp_path):
    report = parse_requirements_txt(
        write_requirements(tmp_path, "requests\nflask==3.0.3\nbad==\n")
    )
    assert [d.name for d in report.unresolved] == ["requests"]
    assert len(report.errors) == 1
    assert isinstance(report, ParseReport)


# ---------------------------------------------------------------------------
# The same rules across the other Python manifests
# ---------------------------------------------------------------------------


def test_pyproject_pep621_preserves_extras_and_pins(tmp_path):
    from checkdeps import parse_pyproject_toml

    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'dependencies = ["uvicorn[standard]==0.34.0", "flask>=2", '
        '"colorama==0.4.6; sys_platform == \\"win32\\""]\n'
        "[project.optional-dependencies]\n"
        'dev = ["pytest==8.0.0"]\n',
        encoding="utf-8",
    )
    report = parse_pyproject_toml(
        tmp_path / "pyproject.toml", environment={"sys_platform": "linux"}
    )
    by_name = {d.name: d for d in report.dependencies}
    assert list(by_name["uvicorn"].extras) == ["standard"]
    assert by_name["uvicorn"].version == "0.34.0"
    assert by_name["flask"].version is None
    assert by_name["pytest"].version == "8.0.0"
    assert "colorama" not in by_name
    assert [d.name for d in report.inactive] == ["colorama"]


def test_poetry_range_is_not_a_resolved_version(tmp_path):
    from checkdeps import parse_pyproject_toml

    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.dependencies]\n"
        'python = "^3.11"\n'
        'click = "8.1.7"\n'
        'rich = "^13.0"\n',
        encoding="utf-8",
    )
    report = parse_pyproject_toml(tmp_path / "pyproject.toml")
    by_name = {d.name: d for d in report.dependencies}
    assert "python" not in by_name
    assert by_name["click"].version == "8.1.7"
    assert by_name["rich"].version is None


def test_pipfile_lock_evaluates_markers(tmp_path):
    from checkdeps import parse_pipfile_lock

    (tmp_path / "Pipfile.lock").write_text(
        '{"default": {"Requests": {"version": "==2.19.1"},'
        ' "colorama": {"version": "==0.4.6",'
        ' "markers": "sys_platform == \'win32\'"}}}',
        encoding="utf-8",
    )
    report = parse_pipfile_lock(
        tmp_path / "Pipfile.lock", environment={"sys_platform": "linux"}
    )
    assert [d.name for d in report.dependencies] == ["requests"]
    assert report.dependencies[0].version == "2.19.1"
    assert [d.name for d in report.inactive] == ["colorama"]


def test_resolve_from_environment_across_manifests(tmp_path):
    from checkdeps import ScanOptions, discover_and_parse

    (tmp_path / "requirements.txt").write_text("flask>=2\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["flask>=2"]\n', encoding="utf-8"
    )
    options = ScanOptions(resolver=VersionResolver(
        environment_versions={"Flask": "3.0.3"}
    ))
    report = discover_and_parse([tmp_path], options=options, quiet=True)
    assert report.unresolved == []
    assert {d.version for d in report.dependencies} == {"3.0.3"}
    assert all(d.resolution == "environment" for d in report.dependencies)
