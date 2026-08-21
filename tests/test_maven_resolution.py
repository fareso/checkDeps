"""
Tests for specs/checkdeps-maven-resolution-spec.md.

The execution tests run a real child process: a stand-in "Maven" is installed
into the project directory as a wrapper and writes a canned dependency tree to
whatever ``-DoutputFile`` names.  That exercises detection, argument building,
process execution, the temporary file and JSON parsing end to end -- everything
except Maven's own resolution, which is precisely the part checkdeps delegates.

The sample projects mirror the spec's integration matrix: explicit versions,
parent-managed and BOM-managed versions, ${property} versions, transitive
dependencies and version conflicts.  Each fixture is the tree Maven reports for
that project, because what checkdeps must get right is using Maven's answer
rather than recomputing it.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import checkdeps
from checkdeps import (
    Dependency,
    MavenErrorKind,
    ScanOptions,
    _dedupe,
    _load_maven_trees,
    _maven_command_line,
    _parse_maven_id,
    discover_and_parse,
    find_maven_command,
    parse_pom,
    resolve_maven_dependencies,
)


# ---------------------------------------------------------------------------
# Dependency-tree fixtures (what Maven reports)
# ---------------------------------------------------------------------------


def node(coord, *children, scope="compile", classifier=""):
    group, artifact, version = coord.split(":")
    return {
        "groupId": group,
        "artifactId": artifact,
        "version": version,
        "type": "jar",
        "scope": scope,
        "classifier": classifier,
        "optional": "false",
        "children": list(children),
    }


def tree(*children):
    root = node("com.example:demo:1.0.0-SNAPSHOT", *children)
    root["scope"] = ""
    return root


# A Spring Boot shaped project: no <version> anywhere in the pom, every version
# supplied by the parent POM and dependency management (spec sections 10, 29).
SPRING_BOOT_TREE = tree(
    node(
        "org.springframework.boot:spring-boot-starter-web:4.0.3",
        node(
            "org.springframework:spring-web:7.0.4",
            node("org.springframework:spring-core:7.0.4"),
        ),
        node("org.springframework:spring-webmvc:7.0.4"),
        node("org.apache.tomcat.embed:tomcat-embed-core:11.0.15"),
    ),
    node(
        "org.springframework.boot:spring-boot-starter-security:4.0.3",
        node("org.springframework.security:spring-security-core:7.0.1"),
    ),
    node("org.postgresql:postgresql:42.7.8", scope="runtime"),
    node("org.springframework.boot:spring-boot-starter-test:4.0.3", scope="test"),
)


SPRING_BOOT_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>4.0.3</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0-SNAPSHOT</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
      <groupId>org.postgresql</groupId>
      <artifactId>postgresql</artifactId>
    </dependency>
  </dependencies>
</project>
"""


# ---------------------------------------------------------------------------
# The stand-in Maven
# ---------------------------------------------------------------------------

FAKE_MAVEN = '''\
import json
import sys
import time
from pathlib import Path

config = json.loads(Path(__file__).with_name("fake_maven_config.json").read_text())

Path(__file__).with_name("fake_maven_argv.json").write_text(
    json.dumps({"argv": sys.argv[1:], "cwd": str(Path.cwd())})
)

if config.get("delay"):
    time.sleep(config["delay"])

output_file = None
for arg in sys.argv[1:]:
    if arg.startswith("-DoutputFile="):
        output_file = Path(arg.split("=", 1)[1])

if output_file is not None and config.get("payload") is not None:
    mode = "a" if "-DappendOutput=true" in sys.argv else "w"
    with open(output_file, mode, encoding="utf-8") as handle:
        handle.write(config["payload"])

sys.stdout.write(config.get("stdout", ""))
sys.stderr.write(config.get("stderr", ""))
sys.exit(config.get("exit_code", 0))
'''


def install_fake_maven(project: Path, *, payload=None, exit_code=0, stdout="",
                       stderr="", delay=0, name=None):
    """Install a fake Maven Wrapper into ``project`` and return its path."""
    project.mkdir(parents=True, exist_ok=True)
    script = project / "fake_maven.py"
    script.write_text(FAKE_MAVEN, encoding="utf-8")
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload)
    (project / "fake_maven_config.json").write_text(
        json.dumps({
            "payload": payload,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "delay": delay,
        }),
        encoding="utf-8",
    )

    if name is None:
        name = "mvnw.cmd" if os.name == "nt" else "mvnw"
    wrapper = project / name
    if name.endswith((".cmd", ".bat")):
        wrapper.write_text(
            "@echo off\r\n"
            f'"{sys.executable}" "{script}" %*\r\n'
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
    else:
        wrapper.write_text(
            "#!/bin/sh\n" f'exec "{sys.executable}" "{script}" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return wrapper


def maven_argv(project: Path) -> dict:
    """What the fake Maven was actually invoked with."""
    return json.loads((project / "fake_maven_argv.json").read_text())


def write_pom(project: Path, body=SPRING_BOOT_POM, name="pom.xml") -> Path:
    project.mkdir(parents=True, exist_ok=True)
    pom = project / name
    pom.write_text(body, encoding="utf-8")
    return pom


def temp_leftovers() -> set:
    return set(Path(tempfile.gettempdir()).glob("checkdeps-maven-*"))


def by_name(deps) -> dict:
    return {dep.name: dep for dep in deps}


# ---------------------------------------------------------------------------
# 1-6: Maven executable detection
# ---------------------------------------------------------------------------


def test_detects_no_maven_when_nothing_is_available(tmp_path, monkeypatch):
    monkeypatch.setattr(checkdeps.shutil, "which", lambda name: None)
    assert find_maven_command(tmp_path) is None


def test_detects_mvn_on_path(tmp_path, monkeypatch):
    monkeypatch.setattr(checkdeps.shutil, "which",
                        lambda name: r"C:\apache-maven\bin\mvn.cmd")
    command = find_maven_command(tmp_path)
    assert command.source == "path"
    assert command.argv == [r"C:\apache-maven\bin\mvn.cmd"]


def test_wrapper_is_preferred_over_global_maven(tmp_path, monkeypatch):
    monkeypatch.setattr(checkdeps.shutil, "which", lambda name: "/usr/bin/mvn")
    wrapper = tmp_path / ("mvnw.cmd" if os.name == "nt" else "mvnw")
    wrapper.write_text("")

    command = find_maven_command(tmp_path)
    assert command.source == "wrapper"
    assert command.argv == [str(wrapper.resolve())]


@pytest.mark.skipif(os.name != "nt", reason="mvnw.cmd is the Windows wrapper")
def test_windows_wrapper_is_mvnw_cmd(tmp_path, monkeypatch):
    monkeypatch.setattr(checkdeps.shutil, "which", lambda name: None)
    (tmp_path / "mvnw").write_text("")          # the Unix wrapper is not runnable
    (tmp_path / "mvnw.cmd").write_text("")
    assert find_maven_command(tmp_path).display.endswith("mvnw.cmd")


@pytest.mark.skipif(os.name == "nt", reason="./mvnw is the Unix wrapper")
def test_unix_wrapper_is_mvnw(tmp_path, monkeypatch):
    monkeypatch.setattr(checkdeps.shutil, "which", lambda name: None)
    (tmp_path / "mvnw").write_text("")
    assert find_maven_command(tmp_path).display.endswith("mvnw")


def test_wrapper_is_found_at_the_reactor_root(tmp_path, monkeypatch):
    """A multi-module build keeps one wrapper at the top, not per module."""
    monkeypatch.setattr(checkdeps.shutil, "which", lambda name: None)
    wrapper = tmp_path / ("mvnw.cmd" if os.name == "nt" else "mvnw")
    wrapper.write_text("")
    module = tmp_path / "service"
    module.mkdir()

    assert find_maven_command(module).display == str(wrapper.resolve())


# ---------------------------------------------------------------------------
# 7-10: dependency-tree parsing
# ---------------------------------------------------------------------------


def test_parses_expanded_json_tree():
    trees = _load_maven_trees(json.dumps(SPRING_BOOT_TREE))
    collected = {}
    checkdeps._dependencies_from_tree(trees[0], "backend/pom.xml", collected)
    deps = by_name(collected.values())

    assert deps["org.springframework:spring-web"].version == "7.0.4"
    assert deps["org.springframework:spring-web"].ecosystem == "Maven"
    assert deps["org.springframework:spring-web"].source_file == "backend/pom.xml"
    assert deps["org.springframework:spring-web"].resolution == "maven"


def test_direct_and_transitive_are_distinguished():
    trees = _load_maven_trees(json.dumps(SPRING_BOOT_TREE))
    collected = {}
    checkdeps._dependencies_from_tree(trees[0], "pom.xml", collected)
    deps = by_name(collected.values())

    assert deps["org.springframework.boot:spring-boot-starter-web"].direct is True
    assert deps["org.postgresql:postgresql"].direct is True
    assert deps["org.springframework:spring-web"].direct is False
    assert deps["org.springframework:spring-core"].direct is False   # depth 3
    assert deps["org.apache.tomcat.embed:tomcat-embed-core"].direct is False


def test_scope_is_preserved():
    trees = _load_maven_trees(json.dumps(SPRING_BOOT_TREE))
    collected = {}
    checkdeps._dependencies_from_tree(trees[0], "pom.xml", collected)
    deps = by_name(collected.values())

    assert deps["org.postgresql:postgresql"].scope == "runtime"
    assert deps["org.postgresql:postgresql"].is_dev is False
    test_dep = deps["org.springframework.boot:spring-boot-starter-test"]
    assert test_dep.scope == "test"
    assert test_dep.is_dev is True


def test_root_project_is_not_reported_as_a_dependency():
    trees = _load_maven_trees(json.dumps(SPRING_BOOT_TREE))
    collected = {}
    checkdeps._dependencies_from_tree(trees[0], "pom.xml", collected)
    assert "com.example:demo" not in by_name(collected.values())


def test_id_only_tree_from_older_plugin_versions():
    """Plugin versions that emit a bare coordinate string are still readable."""
    raw = {
        "id": "com.example:demo:jar:1.0",
        "children": [
            {
                "id": "org.springframework:spring-web:jar:7.0.4:compile",
                "children": [
                    {"id": "org.springframework:spring-core:jar:7.0.4:compile",
                     "children": []}
                ],
            }
        ],
    }
    collected = {}
    checkdeps._dependencies_from_tree(raw, "pom.xml", collected)
    deps = by_name(collected.values())

    assert deps["org.springframework:spring-web"].version == "7.0.4"
    assert deps["org.springframework:spring-web"].scope == "compile"
    assert deps["org.springframework:spring-web"].direct is True
    assert deps["org.springframework:spring-core"].direct is False


@pytest.mark.parametrize("raw, expected", [
    ("g:a:1.0", ("g", "a", "1.0", "", "", "")),
    ("g:a:jar:1.0", ("g", "a", "1.0", "jar", "", "")),
    ("g:a:jar:1.0:compile", ("g", "a", "1.0", "jar", "", "compile")),
    ("g:a:jar:tests:1.0:test", ("g", "a", "1.0", "jar", "tests", "test")),
    ("nonsense", None),
    (None, None),
])
def test_maven_id_shapes(raw, expected):
    assert _parse_maven_id(raw) == expected


def test_classifier_is_kept():
    raw = {"id": "com.example:demo:jar:1.0", "children": [
        {"id": "org.example:library:jar:tests:2.0:test", "children": []}]}
    collected = {}
    checkdeps._dependencies_from_tree(raw, "pom.xml", collected)
    dep = list(collected.values())[0]
    assert dep.classifier == "tests"
    assert dep.artifact_type == "jar"


def test_repeated_subtree_is_recorded_once():
    """Maven prints a shared artifact under every parent that reaches it."""
    shared = node("org.example:shared:1.0")
    payload = tree(node("org.example:a:1.0", shared), node("org.example:b:1.0", shared))
    collected = {}
    checkdeps._dependencies_from_tree(payload, "pom.xml", collected)
    assert [d.name for d in collected.values()].count("org.example:shared") == 1


def test_invalid_json_is_reported_not_raised():
    with pytest.raises(ValueError):
        _load_maven_trees("not json at all")
    with pytest.raises(ValueError):
        _load_maven_trees("   ")


def test_multi_module_output_is_a_stream_of_trees():
    """appendOutput leaves one JSON object per module in the same file."""
    api = tree(node("org.example:library:1.0"))
    api["artifactId"] = "api"
    service = tree(node("org.example:library:1.0"), node("org.example:other:2.0"))
    service["artifactId"] = "service"

    trees = _load_maven_trees(json.dumps(api) + "\n" + json.dumps(service))
    assert len(trees) == 2

    collected = {}
    for one in trees:
        checkdeps._dependencies_from_tree(one, "pom.xml", collected)
    assert sorted(by_name(collected.values())) == [
        "org.example:library", "org.example:other"
    ]


# ---------------------------------------------------------------------------
# 11: deduplication
# ---------------------------------------------------------------------------


def test_same_package_version_across_modules_is_one_osv_query():
    def dep(source, direct=False):
        return Dependency(name="org.springframework:spring-core", version="7.0.4",
                          ecosystem="Maven", source_file=source, direct=direct,
                          resolution="maven")

    unique = _dedupe([dep("backend/api/pom.xml"),
                      dep("backend/service/pom.xml", direct=True)])

    assert len(unique) == 1
    assert unique[0].sources == ["backend/api/pom.xml", "backend/service/pom.xml"]
    assert unique[0].direct is True   # declared in one module, so direct overall


def test_different_versions_are_not_deduplicated():
    def dep(version):
        return Dependency(name="org.example:library", version=version,
                          ecosystem="Maven", source_file="pom.xml",
                          resolution="maven")

    assert len(_dedupe([dep("1.0"), dep("2.0")])) == 2


# ---------------------------------------------------------------------------
# Execution: command construction and the full path through a child process
# ---------------------------------------------------------------------------


def test_command_uses_a_pinned_plugin_and_json_output(tmp_path):
    command = checkdeps.MavenCommand(["mvn"], "mvn", "path")
    argv = _maven_command_line(command, tmp_path / "pom.xml", tmp_path / "out.json")

    goal = f"{checkdeps.MAVEN_DEPENDENCY_PLUGIN}:" \
           f"{checkdeps.MAVEN_DEPENDENCY_PLUGIN_VERSION}:tree"
    assert argv[0] == "mvn"
    assert goal in argv
    assert "-DoutputType=json" in argv
    assert f"-DoutputFile={tmp_path / 'out.json'}" in argv
    # Only dependency inspection: no lifecycle phase is ever requested.
    assert not {"package", "install", "verify", "test", "compile"} & set(argv)


def test_non_default_pom_name_is_passed_with_f(tmp_path):
    command = checkdeps.MavenCommand(["mvn"], "mvn", "path")
    argv = _maven_command_line(command, tmp_path / "backend-pom.xml",
                               tmp_path / "out.json")
    assert argv[argv.index("-f") + 1] == str(tmp_path / "backend-pom.xml")

    argv = _maven_command_line(command, tmp_path / "pom.xml", tmp_path / "out.json")
    assert "-f" not in argv


def test_resolution_runs_maven_in_the_project_directory(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE)

    resolution = resolve_maven_dependencies(pom)

    assert resolution.ok, resolution.reason
    assert Path(maven_argv(project)["cwd"]).resolve() == project.resolve()


def test_resolution_returns_the_graph_maven_reported(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE)

    deps = by_name(resolve_maven_dependencies(pom).dependencies)

    # Declared without a <version>: only Maven knows these (spec 10 and 29).
    assert deps["org.springframework.boot:spring-boot-starter-web"].version == "4.0.3"
    assert deps["org.postgresql:postgresql"].version == "42.7.8"
    # Never named in the pom at all.
    assert deps["org.apache.tomcat.embed:tomcat-embed-core"].version == "11.0.15"
    assert deps["org.springframework.security:spring-security-core"].version == "7.0.1"
    assert all(dep.resolved for dep in deps.values())


def test_paths_containing_spaces(tmp_path):
    project = tmp_path / "my maven project" / "back end"
    pom = write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE)

    resolution = resolve_maven_dependencies(pom)

    assert resolution.ok, resolution.reason
    assert len(resolution.dependencies) == len(by_name(resolution.dependencies))


def test_temporary_file_is_removed_on_success(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE)

    before = temp_leftovers()
    assert resolve_maven_dependencies(pom).ok
    assert temp_leftovers() - before == set()
    # ...and nothing was written into the project either.
    assert not list(project.glob("*dependency*"))


def test_temporary_file_is_removed_on_failure(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, exit_code=1, stdout="[ERROR] boom")

    before = temp_leftovers()
    assert not resolve_maven_dependencies(pom).ok
    assert temp_leftovers() - before == set()


def test_timeout_is_bounded_and_classified(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE, delay=5)

    before = temp_leftovers()
    resolution = resolve_maven_dependencies(pom, timeout=1)

    assert resolution.error == MavenErrorKind.TIMEOUT
    assert "1s" in resolution.reason
    assert temp_leftovers() - before == set()


def test_unstartable_wrapper_is_classified(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    wrapper = install_fake_maven(project, payload=SPRING_BOOT_TREE)
    wrapper.write_text("")          # empty: nothing the OS can execute

    resolution = resolve_maven_dependencies(pom)

    assert resolution.error == MavenErrorKind.NOT_FOUND
    assert "could not start" in resolution.reason


def test_unstartable_wrapper_falls_through_to_maven_on_path(tmp_path, monkeypatch):
    """A checkout that lost the wrapper's executable bit is not a Maven-less project."""
    project = tmp_path / "backend"
    pom = write_pom(project)
    (project / "mvnw").write_text("")           # present, but unusable
    (project / "mvnw.cmd").write_text("")
    on_path = install_fake_maven(project, payload=SPRING_BOOT_TREE, name="mvn-stub.cmd"
                                 if os.name == "nt" else "mvn-stub")
    monkeypatch.setattr(checkdeps.shutil, "which",
                        lambda name: str(on_path) if name == "mvn" else None)

    report = parse_pom(pom, ScanOptions())

    assert by_name(report.dependencies)["org.postgresql:postgresql"].version == "42.7.8"
    assert any("would not start" in note for note in report.notes)


def test_missing_maven_is_classified(tmp_path, monkeypatch):
    monkeypatch.setattr(checkdeps.shutil, "which", lambda name: None)
    resolution = resolve_maven_dependencies(write_pom(tmp_path / "backend"))
    assert resolution.error == MavenErrorKind.NOT_FOUND


def test_unresolvable_artifact_is_classified(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, exit_code=1, stdout=(
        "[INFO] Scanning for projects...\n"
        "[ERROR] Failed to execute goal on project demo: Could not resolve "
        "artifact com.example:internal-lib:2.1.0\n"
    ))

    resolution = resolve_maven_dependencies(pom)

    assert resolution.error == MavenErrorKind.DEPENDENCY_RESOLUTION_FAILED
    assert "com.example:internal-lib:2.1.0" in resolution.reason


def test_unusable_plugin_is_classified(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, exit_code=1, stdout=(
        "[ERROR] Plugin org.apache.maven.plugins:maven-dependency-plugin:3.8.1 "
        "or one of its dependencies could not be resolved\n"
    ))
    assert resolve_maven_dependencies(pom).error == MavenErrorKind.PLUGIN_FAILED


def test_unparseable_output_is_classified(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, payload="<<not json>>")

    resolution = resolve_maven_dependencies(pom)

    assert resolution.error == MavenErrorKind.OUTPUT_INVALID
    assert "JSON" in resolution.reason


def test_missing_output_file_is_classified(tmp_path):
    """Maven claimed success but wrote nothing -- do not report zero deps."""
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, payload=None)

    resolution = resolve_maven_dependencies(pom)
    assert resolution.error == MavenErrorKind.OUTPUT_INVALID


# ---------------------------------------------------------------------------
# parse_pom: Maven first, static pom.xml as the fallback
# ---------------------------------------------------------------------------


def test_parse_pom_uses_maven_without_any_extra_flag(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE)

    report = parse_pom(pom, ScanOptions())      # default options: no opt-in
    deps = by_name(report.dependencies)

    assert deps["org.springframework.boot:spring-boot-starter-web"].version == "4.0.3"
    assert report.unresolved == []
    assert any("Maven detected" in note for note in report.notes)
    assert report.detail == [
        "     [cyan]4[/cyan] direct dependencies",
        "     [cyan]5[/cyan] transitive dependencies",
        "     [cyan]9[/cyan] resolved dependencies",
    ]


def test_parse_pom_falls_back_when_maven_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(checkdeps.shutil, "which", lambda name: None)
    pom = write_pom(tmp_path / "backend")

    report = parse_pom(pom, ScanOptions())

    # The static parser knows the three declared packages and no versions.
    assert len(report.dependencies) == 3
    assert len(report.unresolved) == 3
    assert any("Maven unavailable" in note for note in report.notes)
    assert report.errors == []      # a fallback is not a scan failure


def test_parse_pom_falls_back_when_maven_fails(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, exit_code=1, stdout=(
        "[ERROR] Could not resolve artifact com.example:internal-lib:2.1.0\n"
    ))

    report = parse_pom(pom, ScanOptions())

    assert len(report.dependencies) == 3        # static parser output
    assert any("resolution failed" in note for note in report.notes)
    assert any("com.example:internal-lib:2.1.0" in note for note in report.notes)
    issue = report.issues[0]
    assert issue.kind == "maven_resolution_failed"
    assert issue.severity == "warning"          # never fatal
    assert MavenErrorKind.DEPENDENCY_RESOLUTION_FAILED in issue.message
    assert report.errors == []


def test_verbose_shows_maven_output_only_when_asked(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, exit_code=1, stdout=(
        "[INFO] pages and pages of build log\n"
        "[ERROR] Failed to execute goal on project demo\n"
    ))

    quiet = parse_pom(pom, ScanOptions())
    loud = parse_pom(pom, ScanOptions(verbose=True))

    # Normal operation shows the one-line reason and no Maven log at all.
    assert any("Failed to execute goal" in note for note in quiet.notes)
    assert not any("pages and pages" in note for note in quiet.notes)
    assert any("pages and pages" in note for note in loud.notes)


def test_no_maven_option_never_executes_maven(tmp_path):
    project = tmp_path / "backend"
    pom = write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE)

    report = parse_pom(pom, ScanOptions(no_maven=True))

    assert len(report.unresolved) == 3
    assert not (project / "fake_maven_argv.json").exists()


# ---------------------------------------------------------------------------
# Spec section 28: the integration matrix, resolved through the whole scan
# ---------------------------------------------------------------------------


def scan(project: Path, options=None):
    return discover_and_parse([project], options=options or ScanOptions(), quiet=True)


def test_explicit_version_is_resolved(tmp_path):
    project = tmp_path / "explicit"
    write_pom(project, SPRING_BOOT_POM)
    install_fake_maven(project, payload=tree(node("org.example:library:1.2.3")))

    deps = by_name(scan(project).dependencies)
    assert deps["org.example:library"].version == "1.2.3"


def test_property_version_is_expanded_by_maven(tmp_path):
    """${library.version} is defined in a parent, so only Maven can expand it."""
    project = tmp_path / "property"
    write_pom(project, """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>library</artifactId>
      <version>${library.version}</version>
    </dependency>
  </dependencies>
</project>
""")
    install_fake_maven(project, payload=tree(node("org.example:library:4.5.6")))

    deps = by_name(scan(project).dependencies)
    assert deps["org.example:library"].version == "4.5.6"
    assert scan(project, ScanOptions(no_maven=True)).unresolved != []


def test_transitive_dependencies_reach_the_osv_query(tmp_path):
    project = tmp_path / "transitive"
    write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE)

    report = scan(project)
    scannable = {d.name for d in report.dependencies if d.resolved}

    assert "org.apache.tomcat.embed:tomcat-embed-core" in scannable
    assert "org.springframework:spring-webmvc" in scannable
    assert "org.springframework.security:spring-security-core" in scannable


def test_only_the_maven_selected_version_is_scanned(tmp_path):
    """A -> library:1.0 and B -> library:2.0; Maven mediated to 2.0."""
    project = tmp_path / "conflict"
    write_pom(project)
    install_fake_maven(project, payload=tree(
        node("org.example:a:1.0", node("org.example:library:2.0")),
        node("org.example:b:1.0", node("org.example:library:2.0")),
    ))

    versions = [d.version for d in scan(project).dependencies
                if d.name == "org.example:library"]
    assert versions == ["2.0"]


def test_multi_module_reactor_produces_one_record_per_package_version(tmp_path):
    project = tmp_path / "reactor"
    write_pom(project)
    api = tree(node("org.springframework:spring-core:7.0.4"))
    api["artifactId"] = "api"
    service = tree(node("org.springframework:spring-core:7.0.4"),
                   node("org.example:only-in-service:1.0"))
    service["artifactId"] = "service"
    install_fake_maven(project, payload=json.dumps(api) + json.dumps(service))

    report = scan(project)
    names = [d.name for d in report.dependencies]

    assert names.count("org.springframework:spring-core") == 1
    assert "org.example:only-in-service" in names


def test_skip_dev_still_drops_test_scope(tmp_path):
    project = tmp_path / "scopes"
    write_pom(project)
    install_fake_maven(project, payload=SPRING_BOOT_TREE)

    report = scan(project, ScanOptions(skip_dev=True))
    names = {d.name for d in report.dependencies}

    assert "org.springframework.boot:spring-boot-starter-test" not in names
    assert "org.postgresql:postgresql" in names      # runtime scope is kept


def test_other_ecosystems_are_untouched(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.20"}}), encoding="utf-8"
    )
    deps = by_name(scan(tmp_path).dependencies)
    assert deps["lodash"].version == "4.17.20"
    assert deps["lodash"].direct is True


# ---------------------------------------------------------------------------
# Opt-in: the same path against a real Maven
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("CHECKDEPS_MAVEN_INTEGRATION"),
    reason="set CHECKDEPS_MAVEN_INTEGRATION=1 to run Maven for real (needs network)",
)
def test_real_maven_resolves_a_managed_version(tmp_path):
    project = tmp_path / "real"
    write_pom(project, SPRING_BOOT_POM)

    resolution = resolve_maven_dependencies(project / "pom.xml")

    assert resolution.ok, resolution.reason
    deps = by_name(resolution.dependencies)
    starter = deps["org.springframework.boot:spring-boot-starter-web"]
    assert starter.version and starter.direct
    assert any(not dep.direct for dep in resolution.dependencies)
