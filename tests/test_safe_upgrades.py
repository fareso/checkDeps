import json

import pytest

import checkdeps
from checkdeps import Dependency, ParseReport, Vulnerability


def vulnerability(*versions):
    return Vulnerability("GHSA-test", "Example", "HIGH", None,
                         fixed_versions=list(versions))


def mock_osv(monkeypatch, answers):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"results": answers}

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, json, timeout):
            assert [q["version"] for q in json["queries"]] == ["1.9", "1.10"]
            return Response()

    monkeypatch.setattr(checkdeps.requests, "Session", Session)


def test_upgrade_checks_all_vulnerabilities_and_numeric_order(monkeypatch):
    dep = Dependency("pkg", "1.8", "PyPI", "requirements.txt")
    results = {0: [vulnerability("1.10", "1.9"), vulnerability("1.10")]}
    mock_osv(monkeypatch, [{"vulns": [{"id": "another-advisory"}]}, {}])
    checkdeps._find_safe_upgrades([dep], results)
    assert all(v.next_safe_version == "1.10" for v in results[0])


@pytest.mark.parametrize("answers", [[], [{}, {}, {}],
                                      [{"error": "failed"}, {"next_page_token": "more"}]])
def test_incomplete_results_do_not_claim_safety(monkeypatch, answers):
    dep = Dependency("pkg", "1.8", "npm", "package.json")
    results = {0: [vulnerability("1.9", "1.10")]}
    mock_osv(monkeypatch, answers)
    checkdeps._find_safe_upgrades([dep], results)
    assert results[0][0].next_safe_version is None


def test_fixed_versions_match_package_and_ignore_git():
    dep = Dependency("python-jose", "3.3", "PyPI", "requirements.txt")
    detail = {"affected": [
        {"package": {"name": "python_jose", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "3.4"}]},
                    {"type": "GIT", "events": [{"fixed": "abcdef"}]}]},
        {"package": {"name": "other", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.0"}]}]},
    ]}
    assert checkdeps._fixed_versions(detail, dep) == ["3.4"]


def test_failed_lookup_stays_unknown(monkeypatch):
    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, *args, **kwargs):
            raise checkdeps.requests.Timeout("unavailable")

    monkeypatch.setattr(checkdeps.requests, "Session", Session)
    results = {0: [vulnerability("2.0")]}
    checkdeps._find_safe_upgrades(
        [Dependency("pkg", "1.0", "PyPI", "requirements.txt")], results)
    assert results[0][0].next_safe_version is None


def test_cache_and_json_output(capsys):
    vuln = vulnerability("2.0")
    cached = checkdeps._vulns_to_cache([vuln])
    assert checkdeps._vulns_from_cache({"vulns": cached})[0].fixed_versions == ["2.0"]
    assert checkdeps._vulns_from_cache({"vulns": [{k: v for k, v in cached[0].items()
                                                 if k != "fixed_versions"}]})[0].fixed_versions == []
    vuln.next_safe_version = "2.0"
    report = ParseReport(dependencies=[Dependency("pkg", "1.0", "PyPI", "requirements.txt")])
    checkdeps.print_json_output(report, {0: [vuln]})
    assert json.loads(capsys.readouterr().out)["findings"][0]["next_safe_version"] == "2.0"


def test_table_displays_upgrade(monkeypatch):
    from io import StringIO
    from rich.console import Console

    output = StringIO()
    monkeypatch.setattr(checkdeps, "console", Console(file=output, width=220))
    vuln = vulnerability("2.0")
    vuln.next_safe_version = "2.0"
    report = ParseReport(dependencies=[Dependency("pkg", "1.0", "PyPI", "requirements.txt")])
    checkdeps.print_table_output(report, {0: [vuln]}, "LOW")
    assert "Next safe version" in output.getvalue()
    assert "2.0" in output.getvalue()
