#!/usr/bin/env python3
"""
checkdeps - CVE vulnerability scanner for dependency manifests.

Supported files:
  pom.xml            Maven (Java)
  package.json       npm / Node.js
  requirements.txt   pip (Python)
  Pipfile / Pipfile.lock   Pipenv
  pyproject.toml     Poetry / PEP 621
  Cargo.toml         Cargo (Rust)
  go.mod             Go modules

Maven projects are resolved by Maven itself: when a pom.xml is found, the
project's Maven Wrapper (or mvn from PATH) is asked for the dependency tree, so
versions inherited from parent POMs, BOMs, dependencyManagement and properties
are real, and transitive dependencies are scanned too.  Static pom.xml parsing
remains the fallback for when Maven cannot be run.

Python dependencies are extracted with a real PEP 508 parser: extras, version
specifiers and environment markers are kept as separate fields, names are
canonicalised per PEP 503 and versions are compared per PEP 440.  A version is
only ever reported when it is actually known -- there is no fallback version.

Data source: OSV (https://osv.dev) -- free, no API key required.
"""

import argparse
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, unquote

import requests
from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
OSV_BATCH_LIMIT = 1000
OSV_FETCH_WORKERS = 20  # parallel vuln detail fetches

CACHE_DIR = Path.home() / ".checkDeps"
CACHE_FILE = CACHE_DIR / "cache.json"
CACHE_TTL = 2 * 24 * 3600  # 2 days in seconds

# GitHub Advisory Database uses MODERATE; normalise it to MEDIUM.
_SEVERITY_ALIASES = {"MODERATE": "MEDIUM"}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
}

console = Console()


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

# A dependency records what the manifest actually said.  ``version`` is the
# *resolved* version -- an exact value that may be matched against advisory
# ranges -- and is ``None`` whenever no such value is known.  ``None`` is never
# replaced by a placeholder such as "0.0.0"; an unknown version makes the
# vulnerability match indeterminate, which is reported as such.


@dataclass
class Dependency:
    name: str                       # canonical distribution name (PEP 503)
    version: str | None             # resolved version, or None if unknown
    ecosystem: str
    source_file: str
    is_dev: bool = False
    extras: tuple = ()              # sorted; never affects name/version
    specifier: str | None = None    # full PEP 440 constraint, "" when absent
    marker: str | None = None       # PEP 508 environment marker
    direct_url: str | None = None   # "name @ url" direct reference
    line: int | None = None
    resolution: str | None = None   # how ``version`` was determined
    active: bool = True             # marker evaluated true for the target env
    raw: str | None = None
    scope: str | None = None        # Maven scope: compile/runtime/provided/test
    direct: bool = True             # declared by the project, not pulled in
    artifact_type: str | None = None    # Maven <type>, e.g. jar / pom
    classifier: str | None = None       # Maven <classifier>, when present
    also_used_by: list = field(default_factory=list)  # further source files

    @property
    def resolved(self) -> bool:
        return self.version is not None

    @property
    def location(self) -> str:
        if self.line:
            return f"{self.source_file}:{self.line}"
        return self.source_file

    @property
    def sources(self) -> list:
        """Every manifest this exact package/version was found in."""
        return [self.source_file, *self.also_used_by]

    @property
    def display_name(self) -> str:
        if self.extras:
            return "{}[{}]".format(self.name, ",".join(self.extras))
        return self.name

    @property
    def vulnerability_match(self) -> str:
        """How this record is treated by the matching stage."""
        if not self.active:
            return "skipped"
        if self.version is None:
            return "indeterminate"
        return "attempted"


@dataclass
class ParseIssue:
    kind: str            # parse_error | unresolved_version | ...
    severity: str        # error | warning
    message: str
    source_file: str
    line: int | None = None
    raw: str | None = None

    @property
    def location(self) -> str:
        if self.line:
            return f"{self.source_file}:{self.line}"
        return self.source_file

    @property
    def vulnerability_match(self) -> str:
        return "not_attempted" if self.kind == "parse_error" else "indeterminate"


@dataclass
class ParseReport:
    """Everything a manifest yielded: records, skipped records and problems."""

    dependencies: list = field(default_factory=list)  # active, scannable
    inactive: list = field(default_factory=list)      # marker evaluated false
    issues: list = field(default_factory=list)

    # Console lines belonging to one manifest: ``notes`` are printed before its
    # "ok" line, ``detail`` replaces the usual "(N deps)" suffix underneath it.
    # Both are consumed by the caller that parsed the file, so merge() -- which
    # builds the scan-wide report -- deliberately leaves them behind.
    notes: list = field(default_factory=list)
    detail: list = field(default_factory=list)

    def merge(self, other: "ParseReport") -> None:
        self.dependencies.extend(other.dependencies)
        self.inactive.extend(other.inactive)
        self.issues.extend(other.issues)

    @property
    def errors(self) -> list:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def unresolved(self) -> list:
        return [d for d in self.dependencies if not d.resolved]


@dataclass
class Vulnerability:
    vuln_id: str
    summary: str
    severity: str
    cvss_score: object  # float or None
    aliases: list = field(default_factory=list)
    published: str = ""


# ---------------------------------------------------------------------------
# PEP 440 / PEP 503 / PEP 508 helpers
# ---------------------------------------------------------------------------


def exact_pin(specifier) -> str | None:
    """
    Return the version a specifier pins exactly, or None.

    Only a lone ``==X.Y.Z`` or ``===X.Y.Z`` identifies a single version.  A
    range, wildcard (``==1.2.*``), compatible release (``~=``), exclusion or an
    empty specifier set leaves the version unknown, and unknown stays unknown.
    """
    if specifier is None:
        return None
    if isinstance(specifier, str):
        try:
            specifier = SpecifierSet(specifier)
        except InvalidSpecifier:
            return None
    specs = list(specifier)
    if len(specs) != 1:
        return None
    spec = specs[0]
    if spec.operator not in ("==", "==="):
        return None
    version = spec.version.strip()
    if "*" in version:
        return None
    try:
        Version(version)
    except InvalidVersion:
        # `===` allows an arbitrary string, but a non-PEP 440 value cannot be
        # compared against advisory ranges, so it is not a resolved version.
        return None
    return version


def version_in_specifier(version: str, specifier: str) -> bool:
    """PEP 440 containment test for advisory ranges. Never a string comparison."""
    try:
        return Version(version) in SpecifierSet(specifier, prereleases=True)
    except (InvalidVersion, InvalidSpecifier):
        return False


def _artifact_version(url: str, expected_name: str | None = None) -> str | None:
    """
    Extract the version from an immutable PyPI artifact URL (wheel or sdist).

    A branch or tag reference is mutable and yields None.
    """
    if not url:
        return None
    filename = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    if filename.endswith(".whl"):
        parser = parse_wheel_filename
    elif filename.endswith((".tar.gz", ".zip")):
        parser = parse_sdist_filename
    else:
        return None
    try:
        name, version = parser(filename)[:2]
    except (InvalidWheelFilename, InvalidSdistFilename, InvalidVersion, ValueError):
        return None
    if expected_name and canonicalize_name(name) != canonicalize_name(expected_name):
        return None
    return str(version)


# `extra` is only defined while resolving a distribution's optional
# dependencies. A requirements file has no such context, so a marker that
# depends on it cannot be decided here.
_QUOTED_STRING = re.compile(r"'[^']*'|\"[^\"]*\"")
_EXTRA_VARIABLE = re.compile(r"(?<![\w.])extra(?![\w.])")


def marker_is_active(marker, environment: dict | None) -> tuple:
    """
    Evaluate a PEP 508 marker against the target environment.

    Returns ``(active, note)``.  An undecidable marker keeps the requirement in
    the scan -- a scanner must not silently drop a package -- and explains why.
    """
    if marker is None:
        return True, None
    environment = environment or {}
    text = str(marker)
    if "extra" not in environment and _EXTRA_VARIABLE.search(
        _QUOTED_STRING.sub("''", text)
    ):
        return True, (
            "marker '{}' depends on `extra`, which a requirements file does not "
            "define; requirement kept".format(text)
        )
    try:
        return bool(marker.evaluate(environment or None)), None
    except Exception as e:  # undefined marker variable
        return True, "marker '{}' could not be evaluated ({}); requirement kept".format(
            text, e
        )


class VersionResolver:
    """
    Supplies exact versions from evidence outside the requirement itself:
    an installed environment, or constraint / lockfile pins.
    """

    def __init__(self, environment_versions: dict | None = None,
                 pinned: dict | None = None):
        self._environment = {
            canonicalize_name(k): v for k, v in (environment_versions or {}).items()
        }
        self._pinned = {canonicalize_name(k): v for k, v in (pinned or {}).items()}

    @classmethod
    def from_installed(cls) -> "VersionResolver":
        versions = {}
        for dist in importlib.metadata.distributions():
            try:
                name = dist.metadata["Name"]
                version = dist.version
            except Exception:
                continue
            if name and version:
                versions[canonicalize_name(name)] = version
        return cls(environment_versions=versions)

    def add_pin(self, name: str, version: str) -> None:
        self._pinned.setdefault(canonicalize_name(name), version)

    def environment_version(self, name: str) -> str | None:
        return self._environment.get(canonicalize_name(name))

    def pinned_version(self, name: str) -> str | None:
        return self._pinned.get(canonicalize_name(name))


# ---------------------------------------------------------------------------
# requirements.txt  (PEP 508)
# ---------------------------------------------------------------------------

# Per-requirement options carry no dependency information and are removed from
# the payload before it reaches the PEP 508 parser.
_PER_REQUIREMENT_OPTIONS = re.compile(
    r"(?:^|\s)--(?:hash|global-option|install-option|config-settings)"
    r"(?:[=\s]+\S+)?"
)

_INCLUDE_OPTIONS = {"-r", "--requirement"}
_CONSTRAINT_OPTIONS = {"-c", "--constraint"}
_EDITABLE_OPTIONS = {"-e", "--editable"}

# Global options: they configure pip, never a dependency.
_IGNORED_OPTIONS = {
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
    "--no-index", "--no-binary", "--only-binary", "--prefer-binary",
    "--require-hashes", "--pre", "--trusted-host", "--use-feature",
    "--no-deps", "--proxy", "--cert", "--client-cert", "--src",
    "--no-build-isolation", "--use-pep517", "--check-build-dependencies",
}

_URL_SCHEMES = ("http://", "https://", "file://", "git+", "hg+", "svn+", "bzr+")


def _strip_comment(line: str) -> str:
    """Drop a `#` comment. A `#` glued to a word (e.g. `#egg=`) is not one."""
    return re.sub(r"(^|\s)#.*$", "", line)


def _logical_lines(text: str):
    """
    Yield ``(line_number, text)`` with backslash continuations joined.

    The number reported is the first physical line of the logical line, so
    error locations stay meaningful.
    """
    buffer = ""
    start = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        if start is None:
            start = lineno
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1]
            continue
        buffer += stripped
        yield start, buffer
        buffer = ""
        start = None
    if buffer:
        yield start, buffer


def _split_option(line: str) -> tuple:
    """Split an option line into ``(option, value)``."""
    if line.startswith("--"):
        if "=" in line:
            option, _, value = line.partition("=")
            return option.strip(), value.strip()
        parts = line.split(None, 1)
        return parts[0], (parts[1].strip() if len(parts) > 1 else "")
    # Short option: `-r file`, `-r=file` and `-rfile` are all accepted by pip.
    option = line[:2]
    value = line[2:].strip()
    if value.startswith("="):
        value = value[1:].strip()
    return option, value


def _egg_fragment(url: str) -> str | None:
    match = re.search(r"[#&]egg=([^&\s]+)", url)
    return match.group(1) if match else None


@dataclass
class _RawRequirement:
    requirement: Requirement
    source_file: str
    line: int
    raw: str
    is_constraint: bool


def _collect_requirements(path: Path, report: ParseReport, seen: set,
                          entries: list, is_constraint: bool) -> None:
    """Walk a requirements/constraints file and its includes, detecting cycles."""
    try:
        resolved_path = path.resolve()
    except OSError:
        resolved_path = path
    if resolved_path in seen:
        report.issues.append(
            ParseIssue("include_cycle", "warning",
                       "Circular include of {}; not re-read".format(path), str(path))
        )
        return
    seen.add(resolved_path)

    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as e:
        report.issues.append(
            ParseIssue("parse_error", "error",
                       "Could not read {}: {}".format(path, e), str(path))
        )
        return

    for lineno, logical in _logical_lines(text):
        line = _strip_comment(logical).strip()
        if not line:
            continue

        if line.startswith("-"):
            option, value = _split_option(line)
            if option in _INCLUDE_OPTIONS or option in _CONSTRAINT_OPTIONS:
                if not value:
                    report.issues.append(
                        ParseIssue("parse_error", "error",
                                   "{} without a file path".format(option),
                                   str(path), lineno, line)
                    )
                    continue
                target = (path.parent / value).expanduser()
                _collect_requirements(
                    target, report, seen, entries,
                    is_constraint or option in _CONSTRAINT_OPTIONS,
                )
                continue
            if option in _EDITABLE_OPTIONS:
                _handle_editable(value, path, lineno, line, report, is_constraint)
                continue
            if option in _IGNORED_OPTIONS:
                continue
            report.issues.append(
                ParseIssue("unsupported_option", "warning",
                           "Ignored unrecognised option {}".format(option),
                           str(path), lineno, line)
            )
            continue

        payload = _PER_REQUIREMENT_OPTIONS.sub("", line).strip()
        if not payload:
            continue

        if payload.startswith(_URL_SCHEMES):
            _handle_bare_url(payload, path, lineno, line, report, is_constraint)
            continue

        try:
            requirement = Requirement(payload)
        except InvalidRequirement as e:
            report.issues.append(
                ParseIssue("parse_error", "error",
                           "Invalid requirement: {}".format(e),
                           str(path), lineno, line)
            )
            continue
        entries.append(
            _RawRequirement(requirement, str(path), lineno, line, is_constraint)
        )


def _handle_editable(value: str, path: Path, lineno: int, raw: str,
                     report: ParseReport, is_constraint: bool) -> None:
    """An editable install only names a distribution when it carries `#egg=`."""
    if is_constraint or not value:
        return
    name = _egg_fragment(value)
    if not name:
        # A local editable path is the project under scan, not a dependency.
        if not value.startswith(_URL_SCHEMES):
            return
        report.issues.append(
            ParseIssue("unresolved_editable", "warning",
                       "Editable requirement has no distribution name (#egg=); "
                       "skipped", str(path), lineno, raw)
        )
        return
    report.dependencies.append(
        Dependency(
            name=canonicalize_name(name), version=None, ecosystem="PyPI",
            source_file=str(path), specifier="", direct_url=value,
            line=lineno, raw=raw,
        )
    )


def _handle_bare_url(payload: str, path: Path, lineno: int, raw: str,
                     report: ParseReport, is_constraint: bool) -> None:
    """A bare URL line names a distribution only if its filename identifies one."""
    if is_constraint:
        return
    filename = unquote(urlsplit(payload).path.rsplit("/", 1)[-1])
    name = _egg_fragment(payload)
    version = _artifact_version(payload)
    if name is None:
        try:
            if filename.endswith(".whl"):
                name = str(parse_wheel_filename(filename)[0])
            elif filename.endswith((".tar.gz", ".zip")):
                name = str(parse_sdist_filename(filename)[0])
        except Exception:
            name = None
    if name is None:
        report.issues.append(
            ParseIssue("unresolved_url", "warning",
                       "URL requirement carries no identifiable distribution "
                       "name; skipped", str(path), lineno, raw)
        )
        return
    report.dependencies.append(
        Dependency(
            name=canonicalize_name(name), version=version, ecosystem="PyPI",
            source_file=str(path), specifier="", direct_url=payload,
            line=lineno, resolution="artifact-url" if version else None, raw=raw,
        )
    )


def _dependency_from_requirement(entry: _RawRequirement, environment: dict,
                                 resolver: VersionResolver,
                                 report: ParseReport) -> Dependency:
    requirement = entry.requirement
    name = canonicalize_name(requirement.name)
    extras = tuple(sorted(requirement.extras))
    specifier = str(requirement.specifier)
    marker = str(requirement.marker) if requirement.marker else None

    active, note = marker_is_active(requirement.marker, environment)
    if note:
        report.issues.append(
            ParseIssue("marker_undecidable", "warning", note,
                       entry.source_file, entry.line, entry.raw)
        )

    # Evidence for an exact version, strongest first.  Extras take no part in
    # this: they only select optional dependencies of the distribution.
    version = resolver.environment_version(name)
    resolution = "environment" if version else None
    if version is None and requirement.url:
        version = _artifact_version(requirement.url, requirement.name)
        resolution = "artifact-url" if version else None
    if version is None:
        version = exact_pin(requirement.specifier)
        resolution = "exact-pin" if version else None
    if version is None:
        version = resolver.pinned_version(name)
        resolution = "constraint" if version else None

    return Dependency(
        name=name,
        version=version,
        ecosystem="PyPI",
        source_file=entry.source_file,
        extras=extras,
        specifier=specifier,
        marker=marker,
        direct_url=requirement.url,
        line=entry.line,
        resolution=resolution,
        active=active,
        raw=entry.raw,
    )


def parse_requirements_txt(path: Path, environment: dict | None = None,
                           resolver: VersionResolver | None = None) -> ParseReport:
    """
    Parse a requirements file into dependency records.

    Extras, specifier and marker are preserved as independent fields, the name
    is canonicalised per PEP 503, and the version is filled in only when it is
    actually known.
    """
    report = ParseReport()
    resolver = resolver or VersionResolver()
    entries: list = []
    _collect_requirements(Path(path), report, set(), entries, is_constraint=False)

    # Constraint files install nothing -- they only pin.  Collect their exact
    # pins first so they can resolve otherwise-unpinned requirements.
    for entry in entries:
        if not entry.is_constraint:
            continue
        active, _ = marker_is_active(entry.requirement.marker, environment)
        if not active:
            continue
        pin = exact_pin(entry.requirement.specifier)
        if pin:
            resolver.add_pin(entry.requirement.name, pin)

    for entry in entries:
        if entry.is_constraint:
            continue
        dep = _dependency_from_requirement(entry, environment or {}, resolver, report)
        if dep.active:
            report.dependencies.append(dep)
        else:
            report.inactive.append(dep)
    return report


# ---------------------------------------------------------------------------
# Other manifest parsers
# ---------------------------------------------------------------------------


def _read_error(path: Path, exc: Exception) -> ParseReport:
    return ParseReport(
        issues=[ParseIssue("parse_error", "error",
                           "Could not parse {}: {}".format(path, exc), str(path))]
    )


def _strip_semver_range(version: str) -> str | None:
    """
    Reduce an npm / Cargo range to the concrete version it names, or None.

    A pure wildcard, a dist-tag or a non-registry reference names no version,
    and no version is exactly what gets reported.
    """
    version = version.strip()
    if not version or version in ("*", "x", "X", "latest", "next"):
        return None
    if version.startswith(("file:", "link:", "workspace:", "npm:", "git", "http")):
        return None
    version = re.sub(r"^[\^~>=<]+\s*", "", version).strip()
    parts = version.split()
    version = parts[0].strip() if parts else ""
    if not version or set(version) <= {"*", "x", "X", "."}:
        return None
    return version


def parse_package_json(path: Path) -> ParseReport:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return _read_error(path, e)

    report = ParseReport()
    sections = [
        ("dependencies", False),
        ("devDependencies", True),
        ("peerDependencies", False),
        ("optionalDependencies", False),
    ]
    for section, is_dev in sections:
        for name, version_spec in data.get(section, {}).items():
            if not isinstance(version_spec, str):
                continue
            version = _strip_semver_range(version_spec)
            report.dependencies.append(
                Dependency(name, version, "npm", str(path), is_dev=is_dev,
                           specifier=version_spec,
                           resolution="semver-range" if version else None)
            )
    return report


def parse_pom_xml(path: Path) -> ParseReport:
    try:
        tree = ET.parse(path)
    except Exception as e:
        return _read_error(path, e)

    root = tree.getroot()
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    # Collect <properties> for ${placeholder} resolution
    props: dict = {}
    for prop_block in root.iter(f"{ns}properties"):
        for child in prop_block:
            tag = child.tag.replace(ns, "")
            if child.text:
                props[tag] = child.text.strip()

    def resolve(text: str) -> str:
        for key, val in props.items():
            text = text.replace("${" + key + "}", val)
        return text

    report = ParseReport()
    for dep in root.iter(f"{ns}dependency"):
        group = dep.find(f"{ns}groupId")
        artifact = dep.find(f"{ns}artifactId")
        version_el = dep.find(f"{ns}version")
        scope_el = dep.find(f"{ns}scope")

        if group is None or artifact is None:
            continue

        version = None
        if version_el is not None and version_el.text:
            version = resolve(version_el.text.strip()) or None
            if version and version.startswith("${"):
                version = None  # unresolvable placeholder

        scope = (
            scope_el.text.strip().lower()
            if scope_el is not None and scope_el.text
            else "compile"
        )
        is_dev = scope in ("test", "provided")
        name = f"{group.text.strip()}:{artifact.text.strip()}"
        report.dependencies.append(
            Dependency(name, version, "Maven", str(path), is_dev=is_dev,
                       resolution="manifest" if version else None,
                       scope=scope)
        )
    return report



# ---------------------------------------------------------------------------
# Maven resolution
# ---------------------------------------------------------------------------

# Maven -- not the raw pom.xml -- decides which artifacts a project actually
# uses: parents, dependencyManagement, imported BOMs, ${properties} and
# conflict mediation all live inside Maven's model.  So checkdeps asks Maven
# for the resolved graph and keeps the XML parser above as the fallback for
# when Maven cannot be run.

MAVEN_DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin"
# Pinned so the JSON output type is guaranteed to exist regardless of which
# plugin version the project itself would otherwise select.
MAVEN_DEPENDENCY_PLUGIN_VERSION = "3.8.1"
MAVEN_TIMEOUT_SECONDS = 300

MAVEN_SCOPES = {"compile", "provided", "runtime", "test", "system", "import"}
# Scopes checkdeps treats as dev, matching what the static POM parser has
# always done.  Kept as data so scope filtering can be added later.
MAVEN_DEV_SCOPES = {"test", "provided"}


class MavenErrorKind:
    """Failure categories -- diagnostics match on these, not on log wording."""

    NOT_FOUND = "MAVEN_NOT_FOUND"
    TIMEOUT = "MAVEN_TIMEOUT"
    EXECUTION_FAILED = "MAVEN_EXECUTION_FAILED"
    DEPENDENCY_RESOLUTION_FAILED = "MAVEN_DEPENDENCY_RESOLUTION_FAILED"
    OUTPUT_INVALID = "MAVEN_OUTPUT_INVALID"
    PLUGIN_FAILED = "MAVEN_PLUGIN_FAILED"


@dataclass
class MavenCommand:
    argv: list           # executable, as an argument list -- never a shell string
    display: str         # what to show the user
    source: str          # "wrapper" | "path"


@dataclass
class MavenResolution:
    dependencies: list = field(default_factory=list)
    command: MavenCommand | None = None
    error: str | None = None      # a MavenErrorKind value when it went wrong
    reason: str | None = None     # one concise line explaining the failure
    output: str = ""              # captured Maven log, shown only with --verbose

    @property
    def ok(self) -> bool:
        return self.error is None


def find_maven_command(project_dir: Path) -> MavenCommand | None:
    """
    Locate a Maven to run for ``project_dir``, wrapper first.

    The wrapper is the Maven version the project itself pins, so it resolves
    more reproducibly than whatever happens to be on PATH.  It is searched for
    up the directory tree because in a multi-module build it lives at the
    reactor root, not next to every module's pom.xml.
    """
    wrappers = ("mvnw.cmd", "mvnw.bat") if os.name == "nt" else ("mvnw",)

    try:
        directory = project_dir.resolve()
    except OSError:
        directory = project_dir

    for parent in [directory, *directory.parents]:
        for name in wrappers:
            candidate = parent / name
            if candidate.is_file():
                return MavenCommand([str(candidate)], str(candidate), "wrapper")

    return maven_on_path()


def maven_on_path() -> MavenCommand | None:
    # shutil.which honours PATHEXT, so this finds mvn.cmd on Windows too.
    found = shutil.which("mvn")
    if found:
        return MavenCommand([found], found, "path")
    return None


def _maven_command_line(command: MavenCommand, pom: Path, output_file: Path) -> list:
    argv = [
        *command.argv,
        "-B",  # batch mode: no colour codes, no interactive prompts
        f"{MAVEN_DEPENDENCY_PLUGIN}:{MAVEN_DEPENDENCY_PLUGIN_VERSION}:tree",
        "-DoutputType=json",
        f"-DoutputFile={output_file}",
        # A reactor build writes one tree per module; without this they
        # overwrite each other and only the last module survives.
        "-DappendOutput=true",
    ]
    if pom.name != "pom.xml":
        argv += ["-f", str(pom)]
    return argv


def _classify_maven_failure(output: str) -> tuple:
    """Map a failed Maven run onto (MavenErrorKind, one-line reason)."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    errors = [line for line in lines if line.startswith(("[ERROR]", "[FATAL]"))]

    def first_matching(*needles) -> str | None:
        for line in errors or lines:
            lowered = line.lower()
            if any(needle in lowered for needle in needles):
                return re.sub(r"^\[(ERROR|FATAL)\]\s*", "", line).strip(" -")
        return None

    resolution_hit = first_matching(
        "could not resolve dependencies",
        "could not resolve artifact",
        "could not find artifact",
        "failure to find",
        "non-resolvable parent pom",
        "non-resolvable import pom",
    )
    if resolution_hit:
        return MavenErrorKind.DEPENDENCY_RESOLUTION_FAILED, resolution_hit

    plugin_hit = first_matching("plugin org.apache.maven.plugins", "no plugin found")
    if plugin_hit:
        return MavenErrorKind.PLUGIN_FAILED, plugin_hit

    reason = ""
    for line in errors:
        reason = re.sub(r"^\[(ERROR|FATAL)\]\s*", "", line).strip()
        if reason:
            break
    return MavenErrorKind.EXECUTION_FAILED, reason or "Maven exited with an error"


def _parse_maven_id(raw) -> tuple | None:
    """
    Split a Maven coordinate string into its parts, or return None.

    Accepts ``g:a:version``, ``g:a:type:version``, ``g:a:type:version:scope``
    and ``g:a:type:classifier:version:scope`` -- the shapes plugin versions
    older than the expanded JSON schema emit as a bare ``id``.
    """
    if not isinstance(raw, str):
        return None
    parts = [part.strip() for part in raw.split(":")]
    if len(parts) < 3 or not all(parts[:3]):
        return None
    group, artifact = parts[0], parts[1]
    rest = parts[2:]

    scope = ""
    # A trailing scope only ever follows a type, so a three-part tail is the
    # shortest form that can carry one; that keeps a version named "test" safe.
    if len(rest) >= 3 and rest[-1].lower() in MAVEN_SCOPES:
        scope = rest.pop().lower()

    version = rest[-1]
    artifact_type = rest[0] if len(rest) >= 2 else ""
    classifier = rest[1] if len(rest) >= 3 else ""
    if not version:
        return None
    return group, artifact, version, artifact_type, classifier, scope


def _maven_coordinates(node) -> dict | None:
    """Read one dependency-tree node into plain coordinates, or None."""
    if not isinstance(node, dict):
        return None
    group = str(node.get("groupId") or "").strip()
    artifact = str(node.get("artifactId") or "").strip()
    version = str(node.get("version") or "").strip()
    scope = str(node.get("scope") or "").strip().lower()
    artifact_type = str(node.get("type") or "").strip()
    classifier = str(node.get("classifier") or "").strip()

    if not (group and artifact and version):
        parsed = _parse_maven_id(node.get("id"))
        if parsed is None:
            return None
        group, artifact, version = parsed[0], parsed[1], parsed[2]
        artifact_type = artifact_type or parsed[3]
        classifier = classifier or parsed[4]
        scope = scope or parsed[5]

    return {
        "groupId": group,
        "artifactId": artifact,
        "version": version,
        "scope": scope if scope in MAVEN_SCOPES else "compile",
        "type": artifact_type or "jar",
        "classifier": classifier or None,
    }


def _load_maven_trees(text: str) -> list:
    """
    Decode the plugin's JSON output into one tree per Maven module.

    With ``appendOutput`` a reactor build leaves several top-level objects in
    the file, one after another, which is not a single JSON document.
    """
    decoder = json.JSONDecoder()
    trees: list = []
    index, length = 0, len(text)
    while index < length:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        try:
            tree, index = decoder.raw_decode(text, index)
        except ValueError as exc:
            raise ValueError("Maven dependency tree was not valid JSON") from exc
        trees.append(tree)
    if not trees:
        raise ValueError("Maven produced an empty dependency tree")
    return trees


def _dependencies_from_tree(tree, source: str, into: dict) -> None:
    """
    Walk one module's tree, adding its dependencies to ``into``.

    The root node is the module itself and is skipped; its children are the
    declared (direct) dependencies and everything below them is transitive.
    Maven reports an artifact once per path that reaches it, so the first
    record wins -- but reaching it directly later still promotes it.
    """
    if not isinstance(tree, dict):
        return

    def walk(node, direct: bool) -> None:
        coords = _maven_coordinates(node)
        if coords is None:
            return
        name = "{groupId}:{artifactId}".format(**coords)
        key = (name, coords["version"], coords["classifier"])
        existing = into.get(key)
        if existing is not None:
            existing.direct = existing.direct or direct
            if source != existing.source_file and source not in existing.also_used_by:
                existing.also_used_by.append(source)
            return
        into[key] = Dependency(
            name=name,
            version=coords["version"],
            ecosystem="Maven",
            source_file=source,
            is_dev=coords["scope"] in MAVEN_DEV_SCOPES,
            resolution="maven",
            scope=coords["scope"],
            direct=direct,
            artifact_type=coords["type"],
            classifier=coords["classifier"],
        )
        for child in node.get("children") or []:
            walk(child, False)

    for child in tree.get("children") or []:
        walk(child, True)


def resolve_maven_dependencies(pom: Path, command: MavenCommand | None = None,
                               timeout: int = MAVEN_TIMEOUT_SECONDS
                               ) -> MavenResolution:
    """
    Ask Maven for the resolved dependency graph of ``pom``.

    Runs a single dependency-inspection goal -- never a lifecycle phase such as
    package, install, verify or test -- with the pom's own directory as the
    working directory, so the project's settings.xml, mirrors, credentials and
    local repository apply exactly as they would to a normal build.
    """
    project_dir = pom.parent if str(pom.parent) else Path(".")
    if command is None:
        command = find_maven_command(project_dir)
    if command is None:
        return MavenResolution(
            error=MavenErrorKind.NOT_FOUND,
            reason="no Maven wrapper next to the project and no mvn on PATH",
        )

    handle, temp_name = tempfile.mkstemp(prefix="checkdeps-maven-", suffix=".json")
    os.close(handle)
    output_file = Path(temp_name)
    try:
        argv = _maven_command_line(command, pom, output_file)
        try:
            process = subprocess.run(
                argv,
                cwd=str(project_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return MavenResolution(
                command=command,
                error=MavenErrorKind.TIMEOUT,
                reason=f"Maven did not finish within {timeout}s",
            )
        except OSError as exc:
            return MavenResolution(
                command=command,
                error=MavenErrorKind.NOT_FOUND,
                reason=f"could not start {command.display}: {exc}",
            )

        output = (process.stdout or "") + (process.stderr or "")
        if process.returncode != 0:
            kind, reason = _classify_maven_failure(output)
            return MavenResolution(command=command, error=kind, reason=reason,
                                   output=output)

        try:
            raw = output_file.read_text(encoding="utf-8")
        except OSError as exc:
            return MavenResolution(
                command=command,
                error=MavenErrorKind.OUTPUT_INVALID,
                reason=f"Maven wrote no dependency tree ({exc})",
                output=output,
            )

        try:
            trees = _load_maven_trees(raw)
        except ValueError as exc:
            return MavenResolution(
                command=command,
                error=MavenErrorKind.OUTPUT_INVALID,
                reason=str(exc),
                output=output,
            )

        collected: dict = {}
        for tree in trees:
            _dependencies_from_tree(tree, str(pom), collected)
        return MavenResolution(dependencies=list(collected.values()),
                               command=command, output=output)
    finally:
        # Both paths, always: nothing generated is left in the temp directory,
        # and nothing is ever written into the scanned project.
        try:
            output_file.unlink()
        except OSError:
            pass


def _maven_log_notes(output: str, limit: int = 40) -> list:
    """The tail of a Maven log, indented -- only ever shown with --verbose."""
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    trimmed = lines[-limit:]
    notes = []
    if len(lines) > len(trimmed):
        notes.append(
            f"  [dim]... {len(lines) - len(trimmed)} earlier Maven lines[/dim]"
        )
    notes.extend(f"    [dim]{line}[/dim]" for line in trimmed)
    return notes


def parse_pom(path: Path, options: "ScanOptions | None" = None) -> ParseReport:
    """
    Resolve a pom.xml with Maven, falling back to static XML parsing.

    A fallback is never fatal: a Maven-less or currently unresolvable project
    still gets scanned with whatever the XML alone reveals.
    """
    options = options if options is not None else ScanOptions()

    if options.no_maven:
        report = parse_pom_xml(path)
        report.notes.append(
            "  [dim]Maven resolution disabled; using static pom.xml analysis[/dim]"
        )
        return report

    command = find_maven_command(path.parent)
    if command is None:
        report = parse_pom_xml(path)
        report.notes.append(f"  [yellow]warning[/yellow] Maven unavailable for {path}")
        report.notes.append("  [dim]falling back to static POM analysis[/dim]")
        return report

    notes = [
        f"  [dim]Maven detected:[/dim] {command.display}",
        f"  [dim]Resolving[/dim] {path} [dim]with Maven "
        "(runs the project's own build tooling)...[/dim]",
    ]
    resolution = resolve_maven_dependencies(
        path, command=command, timeout=options.maven_timeout
    )

    # A wrapper that will not start at all -- the usual cause being a checkout
    # that lost the executable bit -- says nothing about the project, so the
    # Maven on PATH still gets its turn before static parsing does.
    if resolution.error == MavenErrorKind.NOT_FOUND and command.source == "wrapper":
        fallback_command = maven_on_path()
        if fallback_command is not None:
            notes.append(
                f"  [yellow]warning[/yellow] {command.display} would not start; "
                f"[dim]trying {fallback_command.display}[/dim]"
            )
            resolution = resolve_maven_dependencies(
                path, command=fallback_command, timeout=options.maven_timeout
            )

    if not resolution.ok:
        report = parse_pom_xml(path)
        report.notes = notes + [
            "  [yellow]warning[/yellow] Maven dependency resolution failed "
            f"[dim]({resolution.error})[/dim]",
            f"  [dim]reason:[/dim] {resolution.reason}",
            "  [dim]Falling back to static POM analysis...[/dim]",
        ]
        if options.verbose and resolution.output:
            report.notes.extend(_maven_log_notes(resolution.output))
        report.issues.append(
            ParseIssue(
                "maven_resolution_failed",
                "warning",
                f"{resolution.error}: {resolution.reason} "
                "(fell back to static pom.xml analysis)",
                str(path),
            )
        )
        return report

    report = ParseReport(dependencies=resolution.dependencies, notes=notes)
    direct = sum(1 for dep in report.dependencies if dep.direct)
    total = len(report.dependencies)
    report.detail = [
        f"     [cyan]{direct}[/cyan] direct dependencies",
        f"     [cyan]{total - direct}[/cyan] transitive dependencies",
        f"     [cyan]{total}[/cyan] resolved dependencies",
    ]
    return report

def parse_pipfile_lock(path: Path, environment: dict | None = None,
                       resolver: VersionResolver | None = None) -> ParseReport:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return _read_error(path, e)

    resolver = resolver or VersionResolver()
    report = ParseReport()
    for section, is_dev in [("default", False), ("develop", True)]:
        for name, info in data.get(section, {}).items():
            if not isinstance(info, dict):
                continue
            canonical = canonicalize_name(name)
            spec = info.get("version") or ""
            version = exact_pin(spec) if spec else None
            resolution = "lockfile" if version else None
            if version is None:
                version = resolver.environment_version(canonical)
                resolution = "environment" if version else None

            marker_text = info.get("markers")
            active, note = _marker_from_text(marker_text, environment, report,
                                             str(path), None, marker_text)
            dep = Dependency(canonical, version, "PyPI", str(path),
                             is_dev=is_dev, specifier=spec, marker=marker_text,
                             resolution=resolution, active=active)
            (report.dependencies if active else report.inactive).append(dep)
    return report


def _marker_from_text(text, environment: dict | None, report: ParseReport,
                      source_file: str, line, raw) -> tuple:
    """Evaluate a marker given as a plain string, recording any problem."""
    if not text:
        return True, None
    try:
        marker = Marker(text)
    except InvalidMarker as e:
        report.issues.append(
            ParseIssue("marker_undecidable", "warning",
                       "Invalid marker {!r} ({}); requirement kept".format(text, e),
                       source_file, line, raw)
        )
        return True, None
    active, note = marker_is_active(marker, environment)
    if note:
        report.issues.append(
            ParseIssue("marker_undecidable", "warning", note, source_file, line, raw)
        )
    return active, note


def _pep440_version(spec) -> str | None:
    """Resolve a PEP 440 specifier or a bare version string to an exact version."""
    if not isinstance(spec, str):
        return None
    spec = spec.strip()
    if not spec or spec == "*":
        return None
    pin = exact_pin(spec)
    if pin:
        return pin
    if spec[0] in "^~<>=!*":
        return None  # a range names no single version
    # Poetry and Pipfile allow a bare version, which means that exact version.
    try:
        Version(spec)
    except InvalidVersion:
        return None
    return spec


def parse_pipfile(path: Path, environment: dict | None = None,
                  resolver: VersionResolver | None = None) -> ParseReport:
    lock_path = path.parent / "Pipfile.lock"
    if lock_path.exists():
        return parse_pipfile_lock(lock_path, environment, resolver)
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return _read_error(path, e)

    resolver = resolver or VersionResolver()
    report = ParseReport()
    for section, is_dev in [("packages", False), ("dev-packages", True)]:
        for name, spec in data.get(section, {}).items():
            canonical = canonicalize_name(name)
            marker_text = None
            if isinstance(spec, str):
                raw = spec
            elif isinstance(spec, dict):
                raw = spec.get("version")
                marker_text = spec.get("markers")
            else:
                raw = None
            version = resolver.environment_version(canonical)
            resolution = "environment" if version else None
            if version is None:
                version = _pep440_version(raw)
                resolution = "exact-pin" if version else None

            active, _ = _marker_from_text(marker_text, environment, report,
                                          str(path), None, marker_text)
            dep = Dependency(canonical, version, "PyPI", str(path),
                             is_dev=is_dev,
                             specifier=raw if isinstance(raw, str) else None,
                             marker=marker_text, resolution=resolution,
                             active=active)
            (report.dependencies if active else report.inactive).append(dep)
    return report


def parse_pyproject_toml(path: Path, environment: dict | None = None,
                         resolver: VersionResolver | None = None) -> ParseReport:
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return _read_error(path, e)

    resolver = resolver or VersionResolver()
    report = ParseReport()

    # PEP 621 / setuptools style: plain PEP 508 requirement strings.
    project = data.get("project", {})
    pep621 = list(project.get("dependencies", []) or [])
    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group in optional.values():
            pep621.extend(group or [])
    for spec in pep621:
        if not isinstance(spec, str):
            continue
        try:
            requirement = Requirement(spec)
        except InvalidRequirement as e:
            report.issues.append(
                ParseIssue("parse_error", "error",
                           "Invalid requirement: {}".format(e), str(path), raw=spec)
            )
            continue
        entry = _RawRequirement(requirement, str(path), None, spec, False)
        dep = _dependency_from_requirement(entry, environment or {}, resolver, report)
        (report.dependencies if dep.active else report.inactive).append(dep)

    # Poetry style: a bare version is exact; `^`, `~` and ranges are not.
    poetry = data.get("tool", {}).get("poetry", {})
    for section, is_dev in [("dependencies", False), ("dev-dependencies", True)]:
        for name, spec in poetry.get(section, {}).items():
            if name.lower() == "python":
                continue
            if isinstance(spec, str):
                raw = spec
            elif isinstance(spec, dict):
                raw = spec.get("version")
            else:
                raw = None
            canonical = canonicalize_name(name)
            version = resolver.environment_version(canonical)
            resolution = "environment" if version else None
            if version is None:
                version = _pep440_version(raw)
                resolution = "exact-pin" if version else None
            report.dependencies.append(
                Dependency(canonical, version, "PyPI", str(path),
                           is_dev=is_dev,
                           specifier=raw if isinstance(raw, str) else None,
                           resolution=resolution)
            )
    return report


def parse_cargo_toml(path: Path) -> ParseReport:
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return _read_error(path, e)

    report = ParseReport()
    for section, is_dev in [
        ("dependencies", False),
        ("dev-dependencies", True),
        ("build-dependencies", False),
    ]:
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                raw = spec
            elif isinstance(spec, dict):
                raw = spec.get("version")
            else:
                continue
            version = _strip_semver_range(raw) if isinstance(raw, str) else None
            report.dependencies.append(
                Dependency(name, version, "crates.io", str(path), is_dev=is_dev,
                           specifier=raw if isinstance(raw, str) else None,
                           resolution="semver-range" if version else None)
            )
    return report


def parse_go_mod(path: Path) -> ParseReport:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except Exception as e:
        return _read_error(path, e)

    report = ParseReport()
    in_require = False
    for lineno, raw in enumerate(lines, 1):
        line = raw.split("//")[0].strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            clean = line.removeprefix("require ").strip()
            parts = clean.split()
            if len(parts) >= 2:
                report.dependencies.append(
                    Dependency(parts[0], parts[1].lstrip("v"), "Go", str(path),
                               line=lineno, resolution="manifest")
                )
    return report


# ---------------------------------------------------------------------------
# File discovery and dispatch
# ---------------------------------------------------------------------------


@dataclass
class ScanOptions:
    """Everything the parsers need to know about the scan target."""

    environment: dict = field(default_factory=dict)   # PEP 508 marker overrides
    resolver: VersionResolver | None = None
    skip_dev: bool = False
    verbose: bool = False
    no_maven: bool = False           # never execute Maven; parse pom.xml only
    maven_timeout: int = MAVEN_TIMEOUT_SECONDS

    def python_parser_kwargs(self) -> dict:
        return {
            "environment": self.environment,
            "resolver": self.resolver or VersionResolver(),
        }


FILE_PARSERS = {
    "pom.xml": parse_pom,
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "Pipfile.lock": parse_pipfile_lock,
    "Pipfile": parse_pipfile,
    "pyproject.toml": parse_pyproject_toml,
    "Cargo.toml": parse_cargo_toml,
    "go.mod": parse_go_mod,
}

# Parsers that accept the scan target environment and the version resolver.
_ENVIRONMENT_AWARE = {
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_pipfile,
    parse_pipfile_lock,
}

# Parsers that shell out to a build tool and need the whole scan options.
_OPTIONS_AWARE = {parse_pom}

# Patterns tried in order when the exact filename doesn't match.
FILE_PATTERNS = [
    (lambda n: n.endswith("pom.xml"),          parse_pom),
    (lambda n: n.endswith("package.json"),     parse_package_json),
    (lambda n: n.endswith("requirements.txt"), parse_requirements_txt),
    (lambda n: n == "Pipfile.lock",            parse_pipfile_lock),
    (lambda n: n == "Pipfile",                 parse_pipfile),
    (lambda n: n.endswith("pyproject.toml"),   parse_pyproject_toml),
    (lambda n: n.endswith("Cargo.toml"),       parse_cargo_toml),
    (lambda n: n == "go.mod",                  parse_go_mod),
]

DETECTION_ORDER = [
    "pom.xml",
    "package.json",
    "requirements.txt",
    "Pipfile.lock",
    "Pipfile",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
]


def _parser_for_file(path: Path):
    """Return the appropriate parser for a file, or None if unsupported."""
    name = path.name
    if name in FILE_PARSERS:
        return FILE_PARSERS[name]
    for matcher, parser in FILE_PATTERNS:
        if matcher(name):
            return parser
    return None


def _run_parser(parser, path: Path, options: ScanOptions) -> ParseReport:
    if parser in _ENVIRONMENT_AWARE:
        kwargs = options.python_parser_kwargs()
    elif parser in _OPTIONS_AWARE:
        kwargs = {"options": options}
    else:
        kwargs = {}
    try:
        return parser(path, **kwargs)
    except Exception as e:  # a broken manifest must not abort the whole scan
        return _read_error(path, e)


def _dedupe(deps: list) -> list:
    """
    Collapse identical records into one, keeping every source they came from.

    The specifier is part of the key so that two unresolved requirements with
    different constraints are not silently merged into one.  Where the same
    resolved package/version does appear in several manifests -- the normal
    case across the modules of a Maven reactor -- it becomes a single OSV
    query, and the other manifests are recorded on the surviving record.
    """
    first_seen: dict = {}
    unique = []
    for dep in deps:
        key = (dep.ecosystem, dep.name, dep.version, dep.specifier)
        kept = first_seen.get(key)
        if kept is None:
            first_seen[key] = dep
            unique.append(dep)
            continue
        if dep.source_file not in kept.sources:
            kept.also_used_by.append(dep.source_file)
        # Declared anywhere means the package is a direct dependency somewhere.
        kept.direct = kept.direct or dep.direct
    return unique


def discover_and_parse(paths: list, skip_dev: bool = False,
                       options: ScanOptions | None = None,
                       quiet: bool = False) -> ParseReport:
    options = options or ScanOptions(skip_dev=skip_dev)
    options.skip_dev = skip_dev or options.skip_dev
    report = ParseReport()

    def announce(target: Path, sub: ParseReport) -> None:
        if quiet:
            return
        for note in sub.notes:
            console.print(note)
        if sub.detail:
            console.print(f"  [green]ok[/green] [bold]{target}[/bold]")
            for line in sub.detail:
                console.print(line)
            return
        unresolved = len(sub.unresolved)
        extra = f", [yellow]{unresolved}[/yellow] unresolved" if unresolved else ""
        console.print(
            f"  [green]ok[/green] [bold]{target}[/bold]  "
            f"([cyan]{len(sub.dependencies)}[/cyan] deps{extra})"
        )

    for p in paths:
        if p.is_dir():
            found_any = False
            for filename in DETECTION_ORDER:
                candidate = p / filename
                if candidate.exists():
                    found_any = True
                    sub = _run_parser(FILE_PARSERS[filename], candidate, options)
                    announce(candidate, sub)
                    report.merge(sub)
            if not found_any and not quiet:
                console.print(
                    f"[yellow]Warning:[/yellow] No supported manifest found in {p}"
                )
        elif p.is_file():
            parser = _parser_for_file(p)
            if parser is None:
                if not quiet:
                    console.print(f"[yellow]Warning:[/yellow] Unsupported file: {p}")
            else:
                sub = _run_parser(parser, p, options)
                announce(p, sub)
                report.merge(sub)
        else:
            report.issues.append(
                ParseIssue("parse_error", "error", f"Path not found: {p}", str(p))
            )
            if not quiet:
                console.print(f"[red]Error:[/red] Path not found: {p}")

    if options.skip_dev:
        before = len(report.dependencies)
        report.dependencies = [d for d in report.dependencies if not d.is_dev]
        skipped = before - len(report.dependencies)
        if skipped and not quiet:
            console.print(f"  [dim]Skipped {skipped} dev dependencies[/dim]")

    report.dependencies = _dedupe(report.dependencies)
    report.inactive = _dedupe(report.inactive)
    return report


# ---------------------------------------------------------------------------
# OSV API
# ---------------------------------------------------------------------------


def _normalise_severity(raw: str) -> str:
    raw = raw.upper().strip()
    return _SEVERITY_ALIASES.get(raw, raw)


def _extract_severity(vuln: dict) -> tuple:
    """
    Return (severity_label, cvss_score_or_None) from a full OSV vuln record.

    OSV full records carry:
      severity[].score  — CVSS vector string (e.g. 'CVSS:3.1/AV:N/...')
      database_specific.severity — qualitative label ('MODERATE', 'HIGH', ...)
    """
    severity = "UNKNOWN"
    score = None

    # Primary: qualitative label in database_specific (e.g. GitHub Advisory DB)
    db_sev = _normalise_severity(
        vuln.get("database_specific", {}).get("severity", "")
    )
    if db_sev in SEVERITY_ORDER:
        severity = db_sev

    # Also scan severity[] for CVSS vectors; extract qualitative rating if possible.
    # CVSS v3 vectors embed the severity in the vector itself via environmental
    # metrics, but the simplest reliable signal is still the database label above.
    # We try a quick heuristic: AV:N + (CI/AI:H) → HIGH/CRITICAL range.
    for sev_entry in vuln.get("severity", []):
        vector = sev_entry.get("score", "")
        if not vector.startswith("CVSS"):
            # Might be a numeric score directly
            try:
                score = float(vector)
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            except (ValueError, TypeError):
                pass

    return severity, score


def _fetch_vuln_detail(vuln_id: str, session: requests.Session) -> dict | None:
    try:
        resp = session.get(OSV_VULN_URL.format(vuln_id), timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Cache  (~/.checkDeps/cache.json, TTL = 2 days)
# ---------------------------------------------------------------------------

# Cache schema:
#   { "<ecosystem>::<name>::<version>": {"expires": <unix_ts>, "vulns": [...]} }
# Each "vulns" entry is a Vulnerability serialised as a plain dict.

def _cache_key(dep: "Dependency") -> str:
    return f"{dep.ecosystem}::{dep.name}::{dep.version}"


def _load_cache() -> dict:
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache), encoding="utf-8")
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not write cache: {e}")


def _vulns_from_cache(entry: dict) -> list:
    return [
        Vulnerability(
            vuln_id=v["vuln_id"],
            summary=v["summary"],
            severity=v["severity"],
            cvss_score=v["cvss_score"],
            aliases=v["aliases"],
            published=v["published"],
        )
        for v in entry["vulns"]
    ]


def _vulns_to_cache(vulns: list) -> list:
    return [
        {
            "vuln_id": v.vuln_id,
            "summary": v.summary,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "aliases": v.aliases,
            "published": v.published,
        }
        for v in vulns
    ]



# ---------------------------------------------------------------------------
# Advisory range matching (PEP 440)
# ---------------------------------------------------------------------------

# The lowest version PEP 440 can express; stands in for OSV's `introduced: "0"`.
_BEGINNING_OF_TIME = Version("0.dev0")


def _osv_range_contains(osv_range: dict, target: Version):
    """
    Evaluate one OSV range against a version.

    Returns True/False, or None when the range cannot be evaluated locally
    (a GIT range, or a bound that is not a PEP 440 version).
    """
    if osv_range.get("type") not in ("ECOSYSTEM", "SEMVER"):
        return None

    events = []
    for event in osv_range.get("events", []):
        for kind in ("introduced", "fixed", "last_affected"):
            if kind not in event:
                continue
            raw = event[kind]
            if kind == "introduced" and raw == "0":
                bound = _BEGINNING_OF_TIME
            else:
                try:
                    bound = Version(raw)
                except InvalidVersion:
                    return None
            events.append((bound, kind))
    if not events:
        return None

    affected = False
    for bound, kind in sorted(events, key=lambda item: item[0]):
        if kind == "introduced":
            if target >= bound:
                affected = True
        elif kind == "fixed":
            if target >= bound:
                affected = False
        elif kind == "last_affected":
            if target > bound:
                affected = False
    return affected


def osv_affects(vuln: dict, ecosystem: str, name: str, version: str):
    """
    Does this advisory actually cover ``name==version``?

    Returns True/False, or None when the record cannot be decided locally --
    in which case the API's own verdict stands.  Only PyPI is evaluated here,
    because only PEP 440 comparison is implemented.
    """
    if ecosystem != "PyPI" or not version:
        return None
    try:
        target = Version(version)
    except InvalidVersion:
        return None

    canonical = canonicalize_name(name)
    matched_package = False
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem", "").split(":")[0] != "PyPI":
            continue
        if canonicalize_name(package.get("name", "")) != canonical:
            continue
        matched_package = True

        ranges = affected.get("ranges", [])
        if ranges:
            for osv_range in ranges:
                verdict = _osv_range_contains(osv_range, target)
                if verdict is None:
                    return None
                if verdict:
                    return True
            continue

        listed = affected.get("versions")
        if not listed:
            return None  # nothing to evaluate; do not second-guess the API
        for candidate in listed:
            try:
                if Version(candidate) == target:
                    return True
            except InvalidVersion:
                continue

    return False if matched_package else None


def query_osv(deps: list, quiet: bool = False) -> dict:
    """
    Two-phase OSV query with a 2-day disk cache.
      Phase 1 -- batch query to get vuln IDs for deps not in cache.
      Phase 2 -- parallel fetch of full vuln records for new unique IDs.
      Phase 3 -- assemble, and re-check each advisory range locally (PEP 440).

    Dependencies with no resolved version are never queried: matching them
    would require a version this tool does not have, and inventing one is
    exactly the bug this contract forbids.  They come back with an empty list
    and are reported as indeterminate.

    Returns {dep_index: [Vulnerability, ...]}.
    """
    results: dict = {i: [] for i in range(len(deps))}
    if not deps:
        return results

    cache = _load_cache()
    now = time.time()
    expires_at = now + CACHE_TTL

    # Split deps into cache hits and misses; skip unresolved ones entirely.
    uncached_indices: list = []
    cache_hits = 0
    for i, dep in enumerate(deps):
        if not dep.resolved:
            continue
        key = _cache_key(dep)
        entry = cache.get(key)
        if entry and entry.get("expires", 0) > now:
            results[i] = _vulns_from_cache(entry)
            cache_hits += 1
        else:
            uncached_indices.append(i)

    if cache_hits and not quiet:
        console.print(
            f"  [dim]Cache: {cache_hits} hit(s), {len(uncached_indices)} miss(es)[/dim]"
        )

    if not uncached_indices:
        return results

    # Phase 1: batch query OSV for uncached deps only
    uncached_deps = [deps[i] for i in uncached_indices]
    dep_vuln_ids: dict = {i: [] for i in uncached_indices}

    with requests.Session() as session:
        for batch_start in range(0, len(uncached_deps), OSV_BATCH_LIMIT):
            batch = uncached_deps[batch_start : batch_start + OSV_BATCH_LIMIT]
            payload = {
                "queries": [
                    {
                        "version": dep.version,
                        "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                    }
                    for dep in batch
                ]
            }
            try:
                resp = session.post(OSV_BATCH_URL, json=payload, timeout=30)
                resp.raise_for_status()
            except requests.RequestException as e:
                # A failed batch is a scan gap, not a clean bill of health --
                # say so on stderr even when stdout must stay machine-readable.
                Console(stderr=True).print(f"[red]OSV API error:[/red] {e}")
                continue

            for rel_idx, result in enumerate(resp.json().get("results", [])):
                abs_idx = uncached_indices[batch_start + rel_idx]
                for v in result.get("vulns", []):
                    dep_vuln_ids[abs_idx].append(v["id"])

        # Phase 2: fetch full details for all new unique IDs in parallel
        all_ids = {vid for ids in dep_vuln_ids.values() for vid in ids}
        vuln_details: dict = {}

        with ThreadPoolExecutor(max_workers=OSV_FETCH_WORKERS) as executor:
            futures = {
                executor.submit(_fetch_vuln_detail, vid, session): vid
                for vid in all_ids
            }
            for future in as_completed(futures):
                vid = futures[future]
                detail = future.result()
                if detail:
                    vuln_details[vid] = detail

    # Phase 3: assemble Vulnerability objects and populate cache for misses
    cache_dirty = False
    filtered_out = 0
    for dep_idx, ids in dep_vuln_ids.items():
        dep = deps[dep_idx]
        vulns: list = []
        for vid in ids:
            detail = vuln_details.get(vid)
            if not detail:
                continue
            if osv_affects(detail, dep.ecosystem, dep.name, dep.version) is False:
                filtered_out += 1
                continue
            severity, score = _extract_severity(detail)
            aliases = [a for a in detail.get("aliases", []) if a != vid]
            vulns.append(
                Vulnerability(
                    vuln_id=vid,
                    summary=detail.get("summary", "No description"),
                    severity=severity,
                    cvss_score=score,
                    aliases=aliases,
                    published=detail.get("published", "")[:10],
                )
            )
        results[dep_idx] = vulns
        key = _cache_key(dep)
        cache[key] = {"expires": expires_at, "vulns": _vulns_to_cache(vulns)}
        cache_dirty = True

    if filtered_out and not quiet:
        console.print(
            f"  [dim]Dropped {filtered_out} advisory hit(s) whose affected range "
            f"does not cover the resolved version[/dim]"
        )

    if cache_dirty:
        _save_cache(cache)

    return results


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------


def severity_text(sev: str) -> Text:
    return Text(sev, style=SEVERITY_COLORS.get(sev, "dim"))


def _filter_by_severity(vulns: list, min_order: int) -> list:
    return [v for v in vulns if SEVERITY_ORDER.get(v.severity, 4) <= min_order]


def _print_unresolved(report: ParseReport) -> None:
    unresolved = report.unresolved
    if not unresolved:
        return
    table = Table(
        title="\n[bold yellow]Unresolved versions -- matching indeterminate[/bold yellow]",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("Package", style="bold", no_wrap=True)
    table.add_column("Ecosystem", no_wrap=True)
    table.add_column("Declared constraint")
    table.add_column("Source", no_wrap=True)
    for dep in unresolved:
        table.add_row(
            dep.display_name,
            dep.ecosystem,
            dep.specifier if dep.specifier else (dep.direct_url or "(none)"),
            dep.location,
        )
    console.print(table)
    console.print(
        "[dim]No exact version is known for these packages, so no advisory "
        "range can be evaluated. Pin them, supply a lockfile, or rerun with "
        "--resolve-from-env.[/dim]"
    )
    if any(dep.ecosystem == "Maven" for dep in unresolved):
        console.print(
            "[dim]The Maven entries above come from static pom.xml analysis. "
            "Letting Maven resolve the project (the default) supplies the "
            "versions its parents, BOMs and properties define.[/dim]"
        )


def print_resolved_maven(report: ParseReport) -> None:
    """List the graph Maven resolved, split into what was declared and what came with it."""
    resolved = [d for d in report.dependencies if d.resolution == "maven"]
    if not resolved:
        return
    for label, group in (
        ("DIRECT", [d for d in resolved if d.direct]),
        ("TRANSITIVE", [d for d in resolved if not d.direct]),
    ):
        if not group:
            continue
        console.print()
        console.print(f"[bold]{label}[/bold]")
        for dep in sorted(group, key=lambda d: (d.name, d.version or "")):
            scope = f" [dim]({dep.scope})[/dim]" if dep.scope else ""
            console.print(f"  {dep.name}:{dep.version}{scope}")
            for extra in dep.also_used_by:
                console.print(f"    [dim]also used by {extra}[/dim]")


def _print_issues(report: ParseReport) -> None:
    if not report.issues:
        return
    errors = [i for i in report.issues if i.severity == "error"]
    warnings = [i for i in report.issues if i.severity != "error"]
    for issue in errors:
        console.print(
            f"[red]error[/red] {issue.location}: {issue.message} "
            f"[dim](vulnerability match: {issue.vulnerability_match})[/dim]"
        )
    for issue in warnings:
        console.print(f"[yellow]warning[/yellow] {issue.location}: {issue.message}")


def print_table_output(report: ParseReport, vuln_map: dict, min_severity: str) -> int:
    min_order = SEVERITY_ORDER.get(min_severity.upper(), 4)
    deps = report.dependencies

    vulnerable = []
    for idx, dep in enumerate(deps):
        vulns = _filter_by_severity(vuln_map.get(idx, []), min_order)
        if vulns:
            vulns.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 4))
            vulnerable.append((dep, vulns))

    if not vulnerable:
        console.print("\n[bold green]No vulnerabilities found![/bold green]")
    else:
        vulnerable.sort(key=lambda pair: SEVERITY_ORDER.get(pair[1][0].severity, 4))

        table = Table(
            title="\n[bold red]Vulnerabilities Found[/bold red]",
            box=box.ROUNDED,
            show_lines=True,
            expand=True,
        )
        table.add_column("Package", style="bold", no_wrap=True)
        table.add_column("Version", no_wrap=True)
        table.add_column("Ecosystem", no_wrap=True)
        table.add_column("Severity", no_wrap=True, justify="center")
        table.add_column("CVE / ID", no_wrap=True)
        table.add_column("Summary")
        table.add_column("Published", no_wrap=True)

        for dep, vulns in vulnerable:
            for i, vuln in enumerate(vulns):
                cve_ids = [vuln.vuln_id] + [a for a in vuln.aliases if "CVE-" in a]
                table.add_row(
                    dep.display_name if i == 0 else "",
                    dep.version if i == 0 else "",
                    dep.ecosystem if i == 0 else "",
                    severity_text(vuln.severity),
                    "\n".join(cve_ids),
                    vuln.summary,
                    vuln.published,
                )

        console.print(table)

    _print_unresolved(report)
    _print_issues(report)

    resolved = sum(1 for d in deps if d.resolved)
    parts = [
        f"[red]{len(vulnerable)}[/red] vulnerable package(s)",
        f"[cyan]{resolved}[/cyan] of [cyan]{len(deps)}[/cyan] dependencies matched",
    ]
    maven = [d for d in deps if d.resolution == "maven"]
    if maven:
        direct = sum(1 for d in maven if d.direct)
        parts.append(
            f"[cyan]{direct}[/cyan] direct + [cyan]{len(maven) - direct}[/cyan] "
            "transitive resolved by Maven"
        )
    if report.unresolved:
        parts.append(f"[yellow]{len(report.unresolved)}[/yellow] indeterminate")
    if report.inactive:
        parts.append(f"[dim]{len(report.inactive)} skipped by marker[/dim]")
    if report.errors:
        parts.append(f"[red]{len(report.errors)}[/red] parse error(s)")
    console.print("\n[bold]Summary:[/bold] " + ", ".join(parts) + ".")
    return len(vulnerable)


def _dependency_json(dep: Dependency) -> dict:
    return {
        "package": dep.name,
        "extras": list(dep.extras),
        "specifier": dep.specifier,
        "resolved_version": dep.version,
        "resolution": dep.resolution,
        "marker": dep.marker,
        "direct_url": dep.direct_url,
        "ecosystem": dep.ecosystem,
        "source": dep.source_file,
        "sources": dep.sources,
        "line": dep.line,
        "dev": dep.is_dev,
        "active": dep.active,
        "scope": dep.scope,
        "direct": dep.direct,
        "type": dep.artifact_type,
        "classifier": dep.classifier,
        "vulnerability_match": dep.vulnerability_match,
    }


def print_json_output(report: ParseReport, vuln_map: dict,
                      min_severity: str = "LOW") -> int:
    min_order = SEVERITY_ORDER.get(min_severity.upper(), 4)
    deps = report.dependencies

    findings = []
    for idx, dep in enumerate(deps):
        vulns = _filter_by_severity(vuln_map.get(idx, []), min_order)
        if not vulns:
            continue
        record = _dependency_json(dep)
        record["vulnerabilities"] = [
            {
                "id": v.vuln_id,
                "aliases": v.aliases,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "summary": v.summary,
                "published": v.published,
            }
            for v in vulns
        ]
        findings.append(record)

    output = {
        "scanned": len(deps),
        "findings": findings,
        "unresolved": [_dependency_json(d) for d in report.unresolved],
        "skipped": [_dependency_json(d) for d in report.inactive],
        "errors": [
            {
                "kind": i.kind,
                "severity": i.severity,
                "message": i.message,
                "source": i.source_file,
                "line": i.line,
                "raw": i.raw,
                "vulnerability_match": i.vulnerability_match,
            }
            for i in report.issues
        ],
    }
    print(json.dumps(output, indent=2))
    return len(findings)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_environment(args) -> dict:
    """Marker overrides describing the environment the scan targets."""
    environment: dict = {}
    if args.python_version:
        environment["python_version"] = args.python_version
        environment["python_full_version"] = args.python_version
    if args.sys_platform:
        environment["sys_platform"] = args.sys_platform
    for item in args.marker_env or []:
        name, sep, value = item.partition("=")
        if not sep:
            console.print(
                f"[red]Error:[/red] --marker-env expects NAME=VALUE, got {item!r}"
            )
            sys.exit(2)
        environment[name.strip()] = value.strip()
    return environment


def main():
    parser = argparse.ArgumentParser(
        prog="checkdeps",
        description="Check dependency files against the OSV CVE database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  checkdeps                          scan current directory
  checkdeps path/to/project          scan a directory
  checkdeps pom.xml package.json     scan specific files
  checkdeps --min-severity HIGH      only show HIGH and CRITICAL
  checkdeps --skip-dev               ignore dev/test dependencies
  checkdeps --format json            machine-readable JSON output
  checkdeps --fail-on-vuln           exit 1 if vulnerabilities found (CI)
  checkdeps --python-version 3.11 --sys-platform linux
                                     evaluate markers for that target
  checkdeps --resolve-from-env       use installed versions where unpinned
  checkdeps --verbose                show the resolved Maven dependency graph
  checkdeps --no-maven               never run Maven; parse pom.xml statically

A pom.xml is resolved by running the project's own Maven (the Maven Wrapper
when there is one, otherwise mvn from PATH) so that versions inherited from
parents, BOMs and properties, plus transitive dependencies, are all scanned.
Only the dependency:tree goal is executed -- never package, install, verify or
test -- and --no-maven turns the execution off entirely.
        """,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Files or directories to scan (default: current directory)",
    )
    parser.add_argument(
        "--min-severity",
        default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        help="Minimum severity level to report (default: LOW)",
    )
    parser.add_argument(
        "--skip-dev",
        action="store_true",
        help="Skip dev/test dependencies",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--fail-on-vuln",
        action="store_true",
        help="Exit with code 1 if vulnerabilities found (useful in CI)",
    )
    parser.add_argument(
        "--fail-on-unresolved",
        action="store_true",
        help="Exit with code 1 if any dependency has no resolved version, or "
             "any requirement failed to parse",
    )
    parser.add_argument(
        "--python-version",
        help="python_version used to evaluate PEP 508 markers "
             "(default: this interpreter)",
    )
    parser.add_argument(
        "--sys-platform",
        help="sys_platform used to evaluate PEP 508 markers "
             "(default: this platform)",
    )
    parser.add_argument(
        "--marker-env",
        action="append",
        metavar="NAME=VALUE",
        help="Additional PEP 508 marker variable; repeatable",
    )
    parser.add_argument(
        "--resolve-from-env",
        action="store_true",
        help="Take exact versions from the installed environment when a "
             "requirement does not pin one",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="List the resolved Maven dependency graph and show Maven's own "
             "output when resolution fails",
    )
    parser.add_argument(
        "--no-maven",
        action="store_true",
        help="Never execute Maven; analyse pom.xml statically instead",
    )
    parser.add_argument(
        "--maven-timeout",
        type=int,
        default=MAVEN_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"Time budget for one Maven resolution "
             f"(default: {MAVEN_TIMEOUT_SECONDS})",
    )

    args = parser.parse_args()
    scan_paths = [Path(p) for p in (args.paths or ["."])]

    quiet = args.format == "json"
    if not quiet:
        console.print("[bold]checkdeps[/bold] -- CVE scanner via OSV (https://osv.dev)\n")
        console.print("[dim]Parsing dependency files...[/dim]")

    options = ScanOptions(
        environment=build_environment(args),
        resolver=(VersionResolver.from_installed() if args.resolve_from_env
                  else VersionResolver()),
        skip_dev=args.skip_dev,
        verbose=args.verbose,
        no_maven=args.no_maven,
        maven_timeout=args.maven_timeout,
    )

    report = discover_and_parse(
        scan_paths, skip_dev=args.skip_dev, options=options, quiet=quiet
    )

    if not report.dependencies:
        if quiet:
            print_json_output(report, {}, min_severity=args.min_severity)
        else:
            console.print("[yellow]No dependencies found to scan.[/yellow]")
            _print_issues(report)
        sys.exit(1 if (args.fail_on_unresolved and report.errors) else 0)

    if args.verbose and not quiet:
        print_resolved_maven(report)

    matchable = sum(1 for d in report.dependencies if d.resolved)
    if not quiet:
        console.print(
            f"\n[dim]Querying OSV API for {matchable} resolved dependencies...[/dim]"
        )

    vuln_map = query_osv(report.dependencies, quiet=quiet)

    if quiet:
        count = print_json_output(report, vuln_map, min_severity=args.min_severity)
    else:
        count = print_table_output(report, vuln_map, min_severity=args.min_severity)

    if args.fail_on_vuln and count > 0:
        sys.exit(1)
    if args.fail_on_unresolved and (report.unresolved or report.errors):
        sys.exit(1)


if __name__ == "__main__":
    main()
