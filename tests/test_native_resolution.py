"""
Tests for specs/checkdeps-native-resolution-platform-install-help-spec.md.

Two things are under test.  First, that every ecosystem asks its own tooling
what the dependency graph actually is, and degrades to static parsing rather
than failing when that tooling is absent.  Second, that an absent tool
produces help somebody can act on: the right platform, a package manager that
is actually installed, and a command that exists in the registry rather than
one assembled on the spot.

External tools are stood in for by real child processes (see fake_tools), so
detection, argument building, exit codes, timeouts and output parsing are
exercised for real.
"""

import json
import os
from pathlib import Path

import pytest

import checkdeps
from checkdeps import (
    APK,
    APT,
    BREW,
    CHOCO,
    DNF,
    PACMAN,
    PROFILES,
    SCOOP,
    TOOLS,
    WINGET,
    ZYPPER,
    MissingTool,
    Platform,
    ScanOptions,
    ToolErrorKind,
    describe_platform,
    detect_package_manager,
    detect_platform,
    discover_and_parse,
    install_advice,
    linux_distribution,
    missing_tool_json,
    missing_tool_lines,
    read_os_release,
    resolution_context,
)
from fake_tools import install_fake_tool, install_on_path, invocations


def scan(project: Path, options=None):
    return discover_and_parse([project], options=options or ScanOptions(),
                              quiet=True)


def record_for(report, ecosystem):
    return next(r for r in report.records if r.ecosystem == ecosystem)


def by_name(deps) -> dict:
    return {dep.name: dep for dep in deps}


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sys_platform, expected", [
    ("win32", Platform.WINDOWS),
    ("darwin", Platform.MACOS),
    ("linux", Platform.LINUX),
    ("linux2", Platform.LINUX),
    ("freebsd14", Platform.OTHER),
    ("emscripten", Platform.OTHER),
])
def test_platform_detection(monkeypatch, sys_platform, expected):
    monkeypatch.setattr(checkdeps.sys, "platform", sys_platform)
    assert detect_platform() == expected


def test_unknown_platform_still_describes_itself(monkeypatch):
    monkeypatch.setattr(checkdeps.sys, "platform", "riscos")
    assert describe_platform() == "this platform"


OS_RELEASE_UBUNTU = '''\
NAME="Ubuntu"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.4 LTS"

# a comment
'''


def test_os_release_parsing(tmp_path):
    path = write(tmp_path / "os-release", OS_RELEASE_UBUNTU)
    values = read_os_release(str(path))

    assert values["ID"] == "ubuntu"
    assert values["ID_LIKE"] == "debian"
    assert values["PRETTY_NAME"] == "Ubuntu 22.04.4 LTS"
    assert "# a comment" not in values


def test_os_release_absent_is_not_an_error(tmp_path):
    assert read_os_release(str(tmp_path / "nothing-here")) == {}
    assert linux_distribution(str(tmp_path / "nothing-here")) == ("", [], "")


def test_linux_distribution_reports_pretty_name(tmp_path):
    path = write(tmp_path / "os-release", OS_RELEASE_UBUNTU)
    distro_id, like, pretty = linux_distribution(str(path))

    assert (distro_id, like) == ("ubuntu", ["debian"])
    assert describe_platform(Platform.LINUX, str(path)) == "Linux: Ubuntu 22.04.4 LTS"


def test_windows_prefers_winget_then_choco_then_scoop(monkeypatch):
    install_on_path(monkeypatch, checkdeps, winget="winget.exe",
                    choco="choco.exe", scoop="scoop.cmd")
    assert detect_package_manager(Platform.WINDOWS).id == WINGET

    install_on_path(monkeypatch, checkdeps, choco="choco.exe", scoop="scoop.cmd")
    assert detect_package_manager(Platform.WINDOWS).id == CHOCO

    install_on_path(monkeypatch, checkdeps, scoop="scoop.cmd")
    assert detect_package_manager(Platform.WINDOWS).id == SCOOP


def test_no_package_manager_is_reported_as_none(monkeypatch):
    install_on_path(monkeypatch, checkdeps)
    assert detect_package_manager(Platform.WINDOWS) is None
    assert detect_package_manager(Platform.MACOS) is None
    assert detect_package_manager(Platform.LINUX) is None
    assert detect_package_manager(Platform.OTHER) is None


def test_macos_uses_homebrew_when_present(monkeypatch):
    install_on_path(monkeypatch, checkdeps, brew="/opt/homebrew/bin/brew")
    assert detect_package_manager(Platform.MACOS).id == BREW


LINUX_CASES = [
    ("ubuntu", "debian", "apt-get", APT),
    ("debian", "", "apt-get", APT),
    ("fedora", "", "dnf", DNF),
    ("rocky", "rhel fedora", "dnf", DNF),
    ("arch", "", "pacman", PACMAN),
    ("opensuse-leap", "suse", "zypper", ZYPPER),
    ("alpine", "", "apk", APK),
]


@pytest.mark.parametrize("distro_id, like, executable, expected", LINUX_CASES)
def test_linux_uses_the_distribution_package_manager(
        monkeypatch, tmp_path, distro_id, like, executable, expected):
    path = write(tmp_path / "os-release",
                 f'ID={distro_id}\nID_LIKE="{like}"\nPRETTY_NAME="Test Linux"\n')
    install_on_path(monkeypatch, checkdeps, **{executable: f"/usr/bin/{executable}"})

    manager = detect_package_manager(Platform.LINUX, str(path))
    assert manager.id == expected


def test_linux_prefers_the_distribution_manager_over_another_installed_one(
        monkeypatch, tmp_path):
    """A container image can carry several; the distribution's own one wins."""
    path = write(tmp_path / "os-release", "ID=fedora\n")
    install_on_path(monkeypatch, checkdeps, dnf="/usr/bin/dnf",
                    **{"apt-get": "/usr/bin/apt-get"})

    assert detect_package_manager(Platform.LINUX, str(path)).id == DNF


def test_unknown_linux_distribution_is_not_guessed(monkeypatch, tmp_path):
    """No ID means no distribution claim -- only what is demonstrably on PATH."""
    path = write(tmp_path / "os-release", "PRETTY_NAME=\"Some Linux\"\n")
    install_on_path(monkeypatch, checkdeps, pacman="/usr/bin/pacman")

    assert detect_package_manager(Platform.LINUX, str(path)).id == PACMAN

    install_on_path(monkeypatch, checkdeps)
    assert detect_package_manager(Platform.LINUX, str(path)) is None


def test_package_manager_selection_is_deterministic(monkeypatch):
    install_on_path(monkeypatch, checkdeps, winget="winget.exe", choco="choco.exe")
    choices = {detect_package_manager(Platform.WINDOWS).id for _ in range(5)}
    assert choices == {WINGET}


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


def test_every_tool_can_explain_itself():
    for tool_id, tool in TOOLS.items():
        assert tool.id == tool_id
        assert tool.display_name and tool.executables and tool.purpose
        assert tool.homepage.startswith("https://")
        assert tool.installers or tool.generic_command


def test_installer_keys_are_known_strategies():
    known = {WINGET, CHOCO, SCOOP, BREW, APT, DNF, PACMAN, ZYPPER, APK}
    for tool in TOOLS.values():
        assert set(tool.installers) <= known
        for command in tool.installers.values():
            assert command.strip() == command and command


def test_every_registered_ecosystem_is_complete():
    """Section 37: no half-registered ecosystem may reach a release."""
    for profile in PROFILES:
        assert profile.ecosystem and profile.osv_ecosystem
        assert profile.manifests, f"{profile.ecosystem} has no manifest"
        assert profile.static_parser is not None, \
            f"{profile.ecosystem} has no static fallback"
        for name in profile.manifests:
            assert name in profile.static_parsers
        for resolver in profile.resolvers:
            assert resolver.id and resolver.label
            if resolver.needs_tool:
                assert resolver.tool_id in TOOLS, \
                    f"{resolver.id} needs an unregistered tool"


def test_the_registry_decides_the_osv_ecosystem(tmp_path):
    """Whatever a parser stamps, the profile's mapping is what OSV is asked."""
    project = tmp_path / "api"
    write(project / "build.gradle", BUILD_GRADLE)
    write(project / "go.mod", GO_MOD)
    write(project / "Cargo.toml", CARGO_TOML)

    report = scan(project)
    by_ecosystem = {d.ecosystem for d in report.dependencies}

    assert by_ecosystem == {"Maven", "Go", "crates.io"}


def test_osv_ecosystems_are_the_names_osv_uses():
    assert {p.osv_ecosystem for p in PROFILES} <= {
        "Maven", "npm", "PyPI", "crates.io", "Go"}


def test_gradle_is_scanned_as_maven_packages():
    """Gradle is a build tool, not an ecosystem: OSV knows these as Maven."""
    assert checkdeps.PROFILES_BY_ECOSYSTEM["Gradle"].osv_ecosystem == "Maven"


# ---------------------------------------------------------------------------
# Missing-tool help
# ---------------------------------------------------------------------------


def missing(tool_id="maven", **kwargs) -> MissingTool:
    defaults = dict(
        tool_id=tool_id,
        command=TOOLS[tool_id].command,
        resolver=tool_id,
        project="backend/pom.xml",
        required_for="the resolved Maven dependency graph",
        fallback="static pom.xml analysis",
    )
    defaults.update(kwargs)
    return MissingTool(**defaults)


def test_windows_help_names_the_platform_installer_and_rerun(monkeypatch):
    install_on_path(monkeypatch, checkdeps, winget="winget.exe")
    lines = missing_tool_lines(missing(), rerun="checkdeps .\\backend",
                               platform=Platform.WINDOWS)
    text = "\n".join(lines)

    assert "Maven is not installed." in text          # tool display name
    assert "(mvn)" in text                            # command name
    assert "resolve the exact versions" in text       # why it is needed
    assert "Windows detected" in text                 # platform
    assert "winget install --id Apache.Maven -e" in text   # install action
    assert "checkdeps .\\backend" in text             # rerun instruction
    assert "Continuing with static pom.xml analysis." in text   # fallback


def test_macos_help_uses_homebrew_when_present(monkeypatch):
    install_on_path(monkeypatch, checkdeps, brew="/opt/homebrew/bin/brew")
    text = "\n".join(missing_tool_lines(missing("pnpm"), platform=Platform.MACOS))

    assert "macOS detected, Homebrew detected." in text
    assert "brew install pnpm" in text


def test_macos_without_homebrew_does_not_recommend_brew(monkeypatch):
    """Section 15: never name a package manager that is not installed."""
    install_on_path(monkeypatch, checkdeps)
    text = "\n".join(missing_tool_lines(missing(), platform=Platform.MACOS))

    assert "brew install" not in text
    assert "no supported package manager was found" in text
    assert TOOLS["maven"].homepage in text


def test_linux_help_follows_the_distribution(monkeypatch, tmp_path):
    path = write(tmp_path / "os-release", "ID=ubuntu\nPRETTY_NAME=\"Ubuntu 22.04\"\n")
    install_on_path(monkeypatch, checkdeps, **{"apt-get": "/usr/bin/apt-get"})
    text = "\n".join(missing_tool_lines(missing("gradle"), platform=Platform.LINUX,
                                        os_release_path=str(path)))

    assert "Linux: Ubuntu 22.04 detected, APT detected." in text
    assert "sudo apt install gradle" in text


def test_unknown_linux_falls_back_to_official_instructions(monkeypatch, tmp_path):
    path = write(tmp_path / "os-release", "PRETTY_NAME=\"Mystery Linux\"\n")
    install_on_path(monkeypatch, checkdeps)
    text = "\n".join(missing_tool_lines(missing("poetry"), platform=Platform.LINUX,
                                        os_release_path=str(path)))

    assert "no supported package manager was found" in text
    # Poetry has a platform-independent command, so that is offered instead.
    assert "pipx install poetry" in text


def test_generic_command_is_used_when_the_manager_has_no_entry(monkeypatch):
    """winget has no registered Poetry package, so nothing is invented."""
    install_on_path(monkeypatch, checkdeps, winget="winget.exe")
    advice = install_advice("poetry", Platform.WINDOWS)

    assert advice.package_manager.id == WINGET
    assert advice.command == "pipx install poetry"
    assert advice.source == "generic"


def test_help_offers_the_homepage_when_nothing_can_be_recommended(monkeypatch):
    install_on_path(monkeypatch, checkdeps)
    advice = install_advice("maven", Platform.OTHER)

    assert advice.command is None
    assert advice.source == "homepage"
    assert TOOLS["maven"].homepage in "\n".join(
        missing_tool_lines(missing(), platform=Platform.OTHER))


def test_version_too_old_reads_differently_from_missing(monkeypatch):
    install_on_path(monkeypatch, checkdeps, brew="/opt/homebrew/bin/brew")
    text = "\n".join(missing_tool_lines(
        missing("pnpm", kind=ToolErrorKind.TOOL_VERSION_TOO_OLD,
                found_version="7.1.0", required_version="9"),
        platform=Platform.MACOS,
    ))

    assert "pnpm 7.1.0 is older than the 9 this resolver needs." in text
    assert "Upgrade pnpm:" in text
    assert "is not installed" not in text


def test_next_step_is_shown_when_the_tool_must_also_be_run(monkeypatch):
    install_on_path(monkeypatch, checkdeps, brew="/opt/homebrew/bin/brew")
    text = "\n".join(missing_tool_lines(
        missing("poetry", next_step="poetry lock"), platform=Platform.MACOS))

    assert "Then run, in the project:" in text
    assert "  poetry lock" in text


def test_help_never_offers_to_install_anything_itself(monkeypatch):
    install_on_path(monkeypatch, checkdeps, winget="winget.exe")
    for tool_id in TOOLS:
        text = "\n".join(missing_tool_lines(missing(tool_id),
                                            platform=Platform.WINDOWS))
        assert "checkdeps will install" not in text.lower()
        assert "installing for you" not in text.lower()


@pytest.mark.parametrize("tool_id", sorted(TOOLS))
@pytest.mark.parametrize("platform", [Platform.WINDOWS, Platform.MACOS,
                                      Platform.LINUX, Platform.OTHER])
def test_every_tool_renders_complete_help_on_every_platform(
        monkeypatch, tmp_path, tool_id, platform):
    """Section 35: the same seven facts, for every registered tool."""
    path = write(tmp_path / "os-release", "ID=ubuntu\n")
    install_on_path(monkeypatch, checkdeps, winget="winget.exe",
                    brew="/opt/homebrew/bin/brew", **{"apt-get": "/usr/bin/apt-get"})
    tool = TOOLS[tool_id]
    lines = missing_tool_lines(missing(tool_id), rerun="checkdeps .",
                               platform=platform, os_release_path=str(path))
    text = "\n".join(lines)

    assert tool.display_name in text
    assert f"({tool.command})" in text
    assert tool.purpose.split()[0] in text
    assert "detected" in text
    assert "Then rerun:" in text and "  checkdeps ." in text
    assert "Continuing with" in text
    # Either a concrete command or the official page -- never nothing.
    advice = install_advice(tool_id, platform, str(path))
    assert (advice.command or advice.homepage) in text


def test_missing_tool_serialises_for_json_output(monkeypatch):
    install_on_path(monkeypatch, checkdeps, winget="winget.exe")
    monkeypatch.setattr(checkdeps.sys, "platform", "win32")
    payload = missing_tool_json(missing())

    assert payload["type"] == "missing_tool"
    assert payload["tool"] == "maven"
    assert payload["displayName"] == "Maven"
    assert payload["platform"] == Platform.WINDOWS
    assert payload["installer"] == WINGET
    assert payload["installCommand"] == "winget install --id Apache.Maven -e"
    assert payload["fallbackUsed"] is True
    assert json.dumps(payload)          # must survive serialisation


# ---------------------------------------------------------------------------
# Resolver behaviour, ecosystem by ecosystem
# ---------------------------------------------------------------------------

GRADLE_REPORT = """\
------------------------------------------------------------
Root project 'demo'
------------------------------------------------------------

annotationProcessor - Annotation processors for source set 'main'.
No dependencies

compileClasspath - Compile classpath for source set 'main'.
+--- com.google.guava:guava:32.1.3-jre
|    +--- com.google.guava:failureaccess:1.0.1
|    \\--- com.google.code.findbugs:jsr305:3.0.2
\\--- org.apache.commons:commons-lang3:3.12.0

implementation - Implementation dependencies for the 'main' feature. (n)
+--- com.google.guava:guava:32.1.3-jre (n)
\\--- org.apache.commons:commons-lang3:3.12.0 (n)

runtimeClasspath - Runtime classpath of source set 'main'.
+--- com.google.guava:guava:32.1.3-jre
|    \\--- com.google.guava:failureaccess:1.0.1
+--- org.apache.commons:commons-lang3:3.11 -> 3.12.0
\\--- org.springframework:spring-core:{strictly 6.1.2} -> 6.1.2

testRuntimeClasspath - Runtime classpath of source set 'test'.
+--- junit:junit:4.13.2
|    \\--- org.hamcrest:hamcrest-core:1.3
\\--- com.google.guava:guava:32.1.3-jre (*)
"""

BUILD_GRADLE = """\
plugins { id 'java' }
repositories { mavenCentral() }
dependencies {
    implementation 'com.google.guava:guava:32.1.3-jre'
    implementation "org.springframework.boot:spring-boot-starter-web"
    implementation "com.example:computed:$libVersion"
    testImplementation 'junit:junit:4.13.2'
    implementation group: 'org.apache.commons', name: 'commons-lang3', version: '3.12.0'
}
"""


def gradle_project(tmp_path: Path) -> Path:
    project = tmp_path / "api"
    write(project / "build.gradle", BUILD_GRADLE)
    return project


def test_gradle_report_parsing():
    deps = by_name(checkdeps.parse_gradle_report(GRADLE_REPORT, "build.gradle",
                                                 "gradle"))

    assert deps["com.google.guava:guava"].version == "32.1.3-jre"
    assert deps["com.google.guava:guava"].direct is True
    assert deps["com.google.guava:failureaccess"].direct is False
    assert deps["com.google.guava:failureaccess"].introduced_by == \
        "com.google.guava:guava"
    # "3.11 -> 3.12.0": the selected version, not the requested one.
    assert deps["org.apache.commons:commons-lang3"].version == "3.12.0"
    assert deps["org.springframework:spring-core"].version == "6.1.2"
    # Test-only configurations stay marked as dev.
    assert deps["junit:junit"].is_dev is True
    assert deps["org.hamcrest:hamcrest-core"].is_dev is True
    # Seen in a non-test configuration too, so guava is not dev.
    assert deps["com.google.guava:guava"].is_dev is False


def test_gradle_declared_but_unresolved_entries_are_dropped():
    """Entries marked (n) are declarations Gradle did not resolve."""
    report = """\
implementation - Implementation dependencies. (n)
+--- org.example:never-resolved:1.0 (n)
"""
    assert checkdeps.parse_gradle_report(report, "build.gradle", "gradle") == []


def test_gradle_wrapper_is_preferred_over_global_gradle(tmp_path, monkeypatch):
    project = gradle_project(tmp_path)
    wrapper_name = "gradlew.bat" if os.name == "nt" else "gradlew"
    install_fake_tool(project, wrapper_name, payload=GRADLE_REPORT)
    global_gradle = install_fake_tool(tmp_path / "bin", "gradle-global.cmd"
                                      if os.name == "nt" else "gradle-global",
                                      payload="")
    install_on_path(monkeypatch, checkdeps, gradle=global_gradle)

    report = scan(project)
    record = record_for(report, "Gradle")

    assert record.native is True
    assert record.resolver == "Gradle Wrapper"
    assert invocations(project, wrapper_name)          # the wrapper ran
    assert not invocations(tmp_path / "bin", "gradle-global")


def test_global_gradle_is_used_when_there_is_no_wrapper(tmp_path, monkeypatch):
    project = gradle_project(tmp_path)
    name = "gradle.cmd" if os.name == "nt" else "gradle"
    tool = install_fake_tool(tmp_path / "bin", name, payload=GRADLE_REPORT)
    install_on_path(monkeypatch, checkdeps, gradle=tool)

    record = record_for(scan(project), "Gradle")

    assert record.native is True
    assert record.resolver == "Gradle"
    assert record.direct == 4 and record.transitive == 3


def test_gradle_resolution_only_runs_the_dependencies_task(tmp_path, monkeypatch):
    project = gradle_project(tmp_path)
    name = "gradle.cmd" if os.name == "nt" else "gradle"
    tool = install_fake_tool(tmp_path / "bin", name, payload=GRADLE_REPORT)
    install_on_path(monkeypatch, checkdeps, gradle=tool)

    scan(project)
    argv = invocations(tmp_path / "bin", name)[0]["argv"]

    assert "dependencies" in argv
    assert not {"build", "assemble", "test", "publish", "install"} & set(argv)


def test_missing_gradle_falls_back_to_the_build_script(tmp_path, monkeypatch):
    install_on_path(monkeypatch, checkdeps)
    project = gradle_project(tmp_path)

    report = scan(project)
    record = record_for(report, "Gradle")
    deps = by_name(report.dependencies)

    assert record.native is False
    assert record.resolver == "static build.gradle analysis"
    assert record.missing_tool.tool_id == "gradle"
    assert deps["com.google.guava:guava"].version == "32.1.3-jre"
    assert deps["junit:junit"].is_dev is True
    # A version the build script computes is not a version.
    assert deps["com.example:computed"].version is None
    assert deps["org.springframework.boot:spring-boot-starter-web"].version is None
    assert report.errors == []


def test_gradle_failure_falls_back_and_keeps_scanning(tmp_path, monkeypatch):
    project = gradle_project(tmp_path)
    name = "gradle.cmd" if os.name == "nt" else "gradle"
    tool = install_fake_tool(tmp_path / "bin", name, exit_code=1, stdout=(
        "FAILURE: Build failed with an exception.\n"
        "* What went wrong:\nCould not resolve all dependencies for "
        "configuration ':runtimeClasspath'.\n"
    ))
    install_on_path(monkeypatch, checkdeps, gradle=tool)

    record = record_for(scan(project), "Gradle")

    assert record.native is False
    assert any(ToolErrorKind.RESOLUTION_FAILED in w for w in record.warnings)
    assert record.total == 5          # the static reading still happened


def test_gradle_reporting_nothing_is_not_treated_as_success(tmp_path, monkeypatch):
    project = gradle_project(tmp_path)
    name = "gradle.cmd" if os.name == "nt" else "gradle"
    tool = install_fake_tool(tmp_path / "bin", name, payload=(
        "compileClasspath - Compile classpath.\n"
        "+--- org.example:broken:1.0 FAILED\n"
    ))
    install_on_path(monkeypatch, checkdeps, gradle=tool)

    record = record_for(scan(project), "Gradle")

    assert record.native is False
    assert any("FAILED" in w for w in record.warnings)


# --- JavaScript -----------------------------------------------------------

PACKAGE_JSON = {
    "name": "app",
    "dependencies": {"axios": "^1.6.0"},
    "devDependencies": {"jest": "^29.0.0"},
}

LOCK_V3 = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"axios": "^1.6.0"},
             "devDependencies": {"jest": "^29.0.0"}},
        "node_modules/axios": {"version": "1.6.0"},
        "node_modules/follow-redirects": {"version": "1.15.4"},
        "node_modules/jest": {"version": "29.7.0", "dev": True},
        "packages/ui": {"resolved": "packages/ui", "link": True},
    },
}

LOCK_V1 = {
    "name": "app",
    "lockfileVersion": 1,
    "dependencies": {
        "axios": {"version": "1.6.0", "requires": {"follow-redirects": "^1.15.0"},
                  "dependencies": {
                      "follow-redirects": {"version": "1.15.4"}}},
        "jest": {"version": "29.7.0", "dev": True},
    },
}


def npm_project(tmp_path: Path, **files) -> Path:
    project = tmp_path / "frontend"
    write(project / "package.json", json.dumps(PACKAGE_JSON))
    for name, content in files.items():
        name = name.replace("_", "-").replace("package-lock", "package-lock")
        write(project / name, content if isinstance(content, str)
              else json.dumps(content))
    return project


def test_npm_lockfile_v3_gives_direct_and_transitive_versions(tmp_path):
    project = npm_project(tmp_path)
    write(project / "package-lock.json", json.dumps(LOCK_V3))

    report = scan(project)
    deps = by_name(report.dependencies)
    record = record_for(report, "npm")

    assert record.native is True and record.resolver == "package-lock.json"
    assert deps["axios"].version == "1.6.0" and deps["axios"].direct is True
    assert deps["follow-redirects"].version == "1.15.4"
    assert deps["follow-redirects"].direct is False
    assert deps["jest"].is_dev is True
    assert "ui" not in deps            # a workspace link is not a package


def test_npm_lockfile_v1_is_read_too(tmp_path):
    project = npm_project(tmp_path)
    write(project / "package-lock.json", json.dumps(LOCK_V1))

    deps = by_name(scan(project).dependencies)

    assert deps["axios"].version == "1.6.0" and deps["axios"].direct is True
    assert deps["follow-redirects"].version == "1.15.4"
    assert deps["follow-redirects"].direct is False


def test_npm_lockfile_supersedes_static_package_json(tmp_path):
    project = npm_project(tmp_path)
    write(project / "package-lock.json", json.dumps(LOCK_V3))

    report = scan(project)

    # One record, one reading: the manifest is not parsed a second time.
    assert len([r for r in report.records if r.ecosystem == "npm"]) == 1
    assert [d.version for d in report.dependencies if d.name == "axios"] == ["1.6.0"]


YARN_CLASSIC = """\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


axios@^1.6.0:
  version "1.6.0"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.6.0.tgz#abc"
  dependencies:
    follow-redirects "^1.15.0"

follow-redirects@^1.15.0:
  version "1.15.4"
  resolved "https://registry.yarnpkg.com/follow-redirects/-/follow-redirects-1.15.4.tgz#def"

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.23.0"
"""

YARN_BERRY = """\
# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10

"axios@npm:^1.6.0":
  version: 1.6.0
  resolution: "axios@npm:1.6.0"
  checksum: abc
  languageName: node
  linkType: hard

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  languageName: unknown

"follow-redirects@npm:^1.15.0":
  version: 1.15.4
  resolution: "follow-redirects@npm:1.15.4"
"""


@pytest.mark.parametrize("lock, expected", [
    (YARN_CLASSIC, {"axios": "1.6.0", "follow-redirects": "1.15.4",
                    "@babel/core": "7.23.0"}),
    (YARN_BERRY, {"axios": "1.6.0", "follow-redirects": "1.15.4"}),
])
def test_yarn_lockfile_generations(tmp_path, lock, expected):
    project = npm_project(tmp_path)
    write(project / "yarn.lock", lock)

    report = scan(project)
    deps = by_name(report.dependencies)

    assert {name: deps[name].version for name in expected} == expected
    assert record_for(report, "npm").resolver == "yarn.lock"
    assert deps["axios"].direct is True
    assert deps["follow-redirects"].direct is False
    # The workspace root is not one of its own dependencies.
    assert "app" not in deps


PNPM_LIST = [{
    "name": "app",
    "version": "1.0.0",
    "dependencies": {
        "axios": {"from": "axios", "version": "1.6.0", "dependencies": {
            "follow-redirects": {"from": "follow-redirects", "version": "1.15.4"}}},
    },
    "devDependencies": {"jest": {"from": "jest", "version": "29.7.0"}},
}]


def test_pnpm_project_is_resolved_by_pnpm(tmp_path, monkeypatch):
    project = npm_project(tmp_path)
    write(project / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
    name = "pnpm.cmd" if os.name == "nt" else "pnpm"
    tool = install_fake_tool(tmp_path / "bin", name, payload=PNPM_LIST,
                             version="9.1.0")
    install_on_path(monkeypatch, checkdeps, pnpm=tool)

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "npm").resolver == "pnpm"
    assert deps["axios"].version == "1.6.0" and deps["axios"].direct is True
    assert deps["follow-redirects"].direct is False
    assert deps["jest"].is_dev is True


def test_missing_pnpm_explains_itself_and_falls_back(tmp_path, monkeypatch):
    install_on_path(monkeypatch, checkdeps)
    project = npm_project(tmp_path)
    write(project / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")

    report = scan(project)
    record = record_for(report, "npm")

    assert record.native is False
    assert record.missing_tool.tool_id == "pnpm"
    assert record.missing_tool.kind == ToolErrorKind.TOOL_NOT_FOUND
    # Whatever package.json alone yields, it is not a resolved graph.
    assert by_name(report.dependencies)["axios"].resolver is None
    assert "follow-redirects" not in by_name(report.dependencies)
    assert report.errors == []


def test_pnpm_that_is_too_old_is_not_the_same_as_missing(tmp_path, monkeypatch):
    project = npm_project(tmp_path)
    write(project / "pnpm-lock.yaml", "lockfileVersion: '5.4'\n")
    name = "pnpm.cmd" if os.name == "nt" else "pnpm"
    tool = install_fake_tool(tmp_path / "bin", name, payload=PNPM_LIST,
                             version="6.35.1")
    install_on_path(monkeypatch, checkdeps, pnpm=tool)

    record = record_for(scan(project), "npm")

    assert record.missing_tool.kind == ToolErrorKind.TOOL_VERSION_TOO_OLD
    assert record.missing_tool.found_version.startswith("6.")
    assert record.native is False


def test_package_manager_field_chooses_the_resolver(tmp_path, monkeypatch):
    """A project that names its manager gets that one, lockfiles notwithstanding."""
    project = tmp_path / "frontend"
    write(project / "package.json", json.dumps({
        **PACKAGE_JSON, "packageManager": "pnpm@9.1.0"}))
    write(project / "package-lock.json", json.dumps(LOCK_V3))
    name = "pnpm.cmd" if os.name == "nt" else "pnpm"
    tool = install_fake_tool(tmp_path / "bin", name, payload=PNPM_LIST,
                             version="9.1.0")
    install_on_path(monkeypatch, checkdeps, pnpm=tool)

    assert record_for(scan(project), "npm").resolver == "pnpm"


def test_npm_tree_is_used_when_only_node_modules_exists(tmp_path, monkeypatch):
    project = npm_project(tmp_path)
    (project / "node_modules").mkdir()
    name = "npm.cmd" if os.name == "nt" else "npm"
    tool = install_fake_tool(tmp_path / "bin", name, payload={
        "name": "app", "version": "1.0.0",
        "dependencies": {"axios": {"version": "1.6.0", "dependencies": {
            "follow-redirects": {"version": "1.15.4"}}}},
    })
    install_on_path(monkeypatch, checkdeps, npm=tool)

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "npm").resolver == "npm"
    assert deps["axios"].direct is True
    assert deps["follow-redirects"].direct is False


# --- Python ---------------------------------------------------------------

UV_LOCK = """\
version = 1
requires-python = ">=3.11"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
"""

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP for Humans"
category = "main"
optional = false

[[package]]
name = "urllib3"
version = "2.0.7"
description = "HTTP library"
category = "main"
optional = false

[[package]]
name = "pytest"
version = "8.0.0"
description = "testing"
category = "dev"
optional = false
"""

POETRY_PYPROJECT = """\
[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
"""


def test_uv_lock_gives_exact_versions_for_the_whole_graph(tmp_path):
    project = tmp_path / "service"
    write(project / "pyproject.toml", '[project]\nname = "demo"\n'
                                      'dependencies = ["requests>=2"]\n')
    write(project / "uv.lock", UV_LOCK)

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "Python").resolver == "uv.lock"
    assert deps["requests"].version == "2.31.0" and deps["requests"].direct
    assert deps["urllib3"].version == "2.0.7"
    assert deps["urllib3"].direct is False
    assert deps["pytest"].is_dev is True
    assert "demo" not in deps          # the project is not its own dependency
    assert report.unresolved == []


def test_poetry_lock_gives_exact_versions(tmp_path):
    project = tmp_path / "service"
    write(project / "pyproject.toml", POETRY_PYPROJECT)
    write(project / "poetry.lock", POETRY_LOCK)

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "Python").resolver == "poetry.lock"
    assert deps["requests"].version == "2.31.0" and deps["requests"].direct
    assert deps["urllib3"].direct is False
    assert deps["pytest"].is_dev is True
    assert report.unresolved == []


def test_pipfile_lock_supersedes_the_pipfile(tmp_path):
    project = tmp_path / "service"
    write(project / "Pipfile", '[packages]\nrequests = "*"\n')
    write(project / "Pipfile.lock", json.dumps({
        "default": {"requests": {"version": "==2.31.0"}},
        "develop": {"pytest": {"version": "==8.0.0"}},
    }))

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "Python").resolver == "Pipfile.lock"
    assert deps["requests"].version == "2.31.0"
    assert deps["pytest"].is_dev is True
    # The unpinned Pipfile entry is not reported alongside the resolved one.
    assert report.unresolved == []


def test_requirements_txt_is_still_parsed_next_to_a_lockfile(tmp_path):
    """A lockfile speaks for pyproject.toml, not for every Python file."""
    project = tmp_path / "service"
    write(project / "pyproject.toml", POETRY_PYPROJECT)
    write(project / "poetry.lock", POETRY_LOCK)
    write(project / "requirements.txt", "flask==3.0.3\n")

    report = scan(project)
    deps = by_name(report.dependencies)

    assert deps["flask"].version == "3.0.3"
    assert deps["requests"].version == "2.31.0"
    assert {r.resolver for r in report.records} == {
        "poetry.lock", "static requirements.txt analysis"}


def test_python_project_without_a_lockfile_says_what_would_help(tmp_path,
                                                                monkeypatch):
    install_on_path(monkeypatch, checkdeps)
    project = tmp_path / "service"
    write(project / "pyproject.toml", POETRY_PYPROJECT)

    report = scan(project)
    record = record_for(report, "Python")

    assert record.native is False
    assert record.missing_tool.tool_id == "poetry"
    assert record.missing_tool.next_step == "poetry lock"
    assert any("Poetry is not installed" in w for w in record.warnings)


def test_installed_manager_without_a_lockfile_is_told_to_lock(tmp_path,
                                                              monkeypatch):
    fake_uv = install_fake_tool(tmp_path / "bin",
                                "uv.cmd" if os.name == "nt" else "uv", version="0.5")
    install_on_path(monkeypatch, checkdeps, uv=fake_uv)
    project = tmp_path / "service"
    write(project / "pyproject.toml", '[project]\nname = "demo"\n'
                                      'dependencies = ["requests>=2"]\n'
                                      '[tool.uv]\ndev-dependencies = []\n')

    record = record_for(scan(project), "Python")

    assert record.missing_tool is None          # uv is installed, so nothing to install
    assert any("uv lock" in w for w in record.warnings)


# --- Rust and Go ----------------------------------------------------------

CARGO_TOML = """\
[package]
name = "engine"
version = "0.1.0"

[dependencies]
regex = "1"

[dev-dependencies]
criterion = "0.5"
"""

CARGO_LOCK = """\
version = 3

[[package]]
name = "engine"
version = "0.1.0"
dependencies = ["regex"]

[[package]]
name = "regex"
version = "1.10.2"
dependencies = ["memchr"]

[[package]]
name = "memchr"
version = "2.7.1"

[[package]]
name = "criterion"
version = "0.5.1"
"""


def test_cargo_lock_gives_the_resolved_crate_graph(tmp_path):
    project = tmp_path / "engine"
    write(project / "Cargo.toml", CARGO_TOML)
    write(project / "Cargo.lock", CARGO_LOCK)

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "Rust").resolver == "Cargo.lock"
    assert deps["regex"].version == "1.10.2" and deps["regex"].direct is True
    assert deps["memchr"].direct is False
    assert deps["criterion"].is_dev is True
    assert "engine" not in deps
    assert report.unresolved == []


def test_cargo_metadata_is_used_when_there_is_no_lockfile(tmp_path, monkeypatch):
    project = tmp_path / "engine"
    write(project / "Cargo.toml", CARGO_TOML)
    name = "cargo.cmd" if os.name == "nt" else "cargo"
    tool = install_fake_tool(tmp_path / "bin", name, payload={
        "packages": [
            {"id": "engine 0.1.0", "name": "engine", "version": "0.1.0"},
            {"id": "regex 1.10.2", "name": "regex", "version": "1.10.2"},
            {"id": "memchr 2.7.1", "name": "memchr", "version": "2.7.1"},
        ],
        "workspace_members": ["engine 0.1.0"],
        "resolve": {"root": "engine 0.1.0", "nodes": [
            {"id": "engine 0.1.0", "deps": [{"name": "regex"}]},
        ]},
    })
    install_on_path(monkeypatch, checkdeps, cargo=tool)

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "Rust").resolver == "cargo metadata"
    assert deps["regex"].direct is True and deps["memchr"].direct is False
    assert "engine" not in deps


GO_MOD = """\
module example.com/app

go 1.21

require (
    github.com/pkg/errors v0.9.1
    golang.org/x/text v0.3.7 // indirect
)
"""

GO_LIST = """\
{"Path":"example.com/app","Main":true,"Dir":"/app"}
{"Path":"github.com/pkg/errors","Version":"v0.9.1"}
{"Path":"golang.org/x/text","Version":"v0.3.7","Indirect":true,
 "Replace":{"Path":"golang.org/x/text","Version":"v0.3.8"}}
"""


def test_go_list_reports_the_selected_module_versions(tmp_path, monkeypatch):
    project = tmp_path / "app"
    write(project / "go.mod", GO_MOD)
    name = "go.cmd" if os.name == "nt" else "go"
    tool = install_fake_tool(tmp_path / "bin", name, payload=GO_LIST)
    install_on_path(monkeypatch, checkdeps, go=tool)

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "Go").resolver == "go list"
    assert deps["github.com/pkg/errors"].version == "0.9.1"
    assert deps["github.com/pkg/errors"].direct is True
    # A replace directive decides what is actually built.
    assert deps["golang.org/x/text"].version == "0.3.8"
    assert deps["golang.org/x/text"].direct is False
    assert "example.com/app" not in deps


def test_missing_go_falls_back_to_go_mod(tmp_path, monkeypatch):
    install_on_path(monkeypatch, checkdeps)
    project = tmp_path / "app"
    write(project / "go.mod", GO_MOD)

    report = scan(project)
    record = record_for(report, "Go")

    assert record.native is False
    assert record.missing_tool.tool_id == "go"
    assert by_name(report.dependencies)["github.com/pkg/errors"].version == "0.9.1"


# ---------------------------------------------------------------------------
# Cross-cutting behaviour
# ---------------------------------------------------------------------------


def test_one_failing_resolver_does_not_stop_the_other_ecosystems(tmp_path,
                                                                 monkeypatch):
    install_on_path(monkeypatch, checkdeps)          # nothing is installed
    project = tmp_path / "mixed"
    write(project / "build.gradle", BUILD_GRADLE)          # needs Gradle
    write(project / "package.json", json.dumps(PACKAGE_JSON))
    write(project / "package-lock.json", json.dumps(LOCK_V3))
    write(project / "requirements.txt", "flask==3.0.3\n")

    report = scan(project)
    deps = by_name(report.dependencies)

    assert record_for(report, "Gradle").missing_tool.tool_id == "gradle"
    assert record_for(report, "npm").native is True
    assert deps["axios"].version == "1.6.0"
    assert deps["flask"].version == "3.0.3"
    assert deps["com.google.guava:guava"].version == "32.1.3-jre"
    assert report.errors == []


def test_no_native_disables_every_resolver(tmp_path):
    project = tmp_path / "mixed"
    write(project / "package.json", json.dumps(PACKAGE_JSON))
    write(project / "package-lock.json", json.dumps(LOCK_V3))

    report = scan(project, ScanOptions(no_native=True))

    assert record_for(report, "npm").native is False
    assert by_name(report.dependencies)["axios"].resolver is None
    assert "follow-redirects" not in by_name(report.dependencies)


def test_strict_mode_turns_a_missing_tool_into_an_error(tmp_path, monkeypatch):
    install_on_path(monkeypatch, checkdeps)
    project = tmp_path / "api"
    write(project / "build.gradle", BUILD_GRADLE)

    lenient = scan(project)
    strict = scan(project, ScanOptions(require_native=True))

    assert lenient.errors == []                     # the default never fails
    assert [i.kind for i in strict.errors] == ["native_resolution_required"]
    # Even in strict mode the static reading still happened.
    assert strict.dependencies


def test_strict_mode_is_satisfied_by_a_lockfile(tmp_path):
    project = tmp_path / "frontend"
    write(project / "package.json", json.dumps(PACKAGE_JSON))
    write(project / "package-lock.json", json.dumps(LOCK_V3))

    assert scan(project, ScanOptions(require_native=True)).errors == []


def test_a_scan_never_runs_an_installation_command(tmp_path, monkeypatch):
    """Section 21: checkdeps explains how to install; it does not install."""
    executed = []
    original = checkdeps.subprocess.run

    def record_run(argv, *args, **kwargs):
        executed.append(argv)
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(checkdeps.subprocess, "run", record_run)
    install_on_path(monkeypatch, checkdeps)
    project = tmp_path / "api"
    write(project / "build.gradle", BUILD_GRADLE)
    write(project / "pyproject.toml", POETRY_PYPROJECT)

    scan(project)

    forbidden = ("winget", "choco", "scoop", "brew", "apt", "apt-get", "dnf",
                 "pacman", "zypper", "apk", "pipx", "npm")
    for argv in executed:
        assert Path(str(argv[0])).stem not in forbidden
        assert "install" not in [str(a) for a in argv]


@pytest.mark.parametrize("line, secret", [
    ("Downloading from central: https://ci:s3cr3t@nexus.corp/a.jar", "s3cr3t"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload", "eyJhbGciOiJIUzI1NiJ9"),
    ("mvn -Dpassword=hunter2 -DskipTests", "hunter2"),
    ("npm config: //registry.npmjs.org/:_authToken=npm_abcdef", "npm_abcdef"),
])
def test_tool_output_is_redacted_before_it_is_shown(line, secret):
    """Section 27: a verbose log must not leak the credentials it quotes."""
    redacted = checkdeps.redact_secrets(line)
    assert secret not in redacted
    assert "***" in redacted


def test_ordinary_tool_output_survives_redaction_unchanged():
    line = "Downloading spring-core-6.1.2.jar from https://repo.maven.apache.org"
    assert checkdeps.redact_secrets(line) == line


def test_verbose_records_the_tool_and_its_version(tmp_path, monkeypatch):
    project = gradle_project(tmp_path)
    name = "gradle.cmd" if os.name == "nt" else "gradle"
    tool = install_fake_tool(tmp_path / "bin", name, payload=GRADLE_REPORT,
                             version="Gradle 8.6")
    install_on_path(monkeypatch, checkdeps, gradle=tool)

    record = record_for(scan(project, ScanOptions(verbose=True)), "Gradle")
    diagnostics = "\n".join(record.diagnostics)

    assert "Gradle: " in diagnostics                 # which executable
    assert "Gradle 8.6" in diagnostics               # its version
    assert "resolution command:" in diagnostics      # what was run
    assert "dependencies" in diagnostics


def test_a_quiet_scan_keeps_the_tool_log_to_itself(tmp_path, monkeypatch):
    project = gradle_project(tmp_path)
    name = "gradle.cmd" if os.name == "nt" else "gradle"
    tool = install_fake_tool(tmp_path / "bin", name, exit_code=1,
                             stdout="secret-looking build log line\n")
    install_on_path(monkeypatch, checkdeps, gradle=tool)

    record = record_for(scan(project), "Gradle")

    assert not any("secret-looking" in line for line in record.diagnostics)


def test_dependencies_are_deduplicated_across_modules(tmp_path):
    root = tmp_path / "repo"
    for module in ("api", "web"):
        write(root / module / "package.json", json.dumps(PACKAGE_JSON))
        write(root / module / "package-lock.json", json.dumps(LOCK_V3))

    report = discover_and_parse([root / "api", root / "web"],
                                options=ScanOptions(), quiet=True)
    axios = [d for d in report.dependencies if d.name == "axios"]

    assert len(axios) == 1                     # one package, one OSV query
    assert len(axios[0].sources) == 2          # both modules still recorded


def test_json_output_carries_resolution_and_missing_tools(tmp_path, monkeypatch,
                                                          capsys):
    install_on_path(monkeypatch, checkdeps)
    project = tmp_path / "api"
    write(project / "build.gradle", BUILD_GRADLE)

    report = scan(project)
    checkdeps.print_json_output(report, {})
    payload = json.loads(capsys.readouterr().out)

    assert payload["resolution"][0]["ecosystem"] == "Gradle"
    assert payload["resolution"][0]["native"] is False
    assert payload["missing_tools"][0]["tool"] == "gradle"
    assert payload["missing_tools"][0]["fallbackUsed"] is True


def test_resolution_context_sees_only_this_project(tmp_path):
    write(tmp_path / "parent" / "package.json", "{}")
    project = tmp_path / "parent" / "child"
    write(project / "pom.xml", "<project/>")

    ctx = resolution_context(checkdeps.PROFILES_BY_ECOSYSTEM["npm"], project)
    assert ctx.files == {}
