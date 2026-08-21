#!/usr/bin/env python3
"""
checkdeps - CVE vulnerability scanner for dependency manifests.

Supported files:
  pom.xml                        Maven (Java)
  build.gradle[.kts]             Gradle (Java)
  package.json + lockfiles       npm / Yarn / pnpm (Node.js)
  requirements.txt               pip (Python)
  Pipfile / Pipfile.lock         Pipenv (Python)
  pyproject.toml + uv.lock / poetry.lock   uv / Poetry / PEP 621 (Python)
  Cargo.toml / Cargo.lock        Cargo (Rust)
  go.mod                         Go modules

Every ecosystem is resolved by its own tooling wherever that is possible:
Maven and Gradle (project wrapper first) for Java, the npm/Yarn lockfile or
pnpm for JavaScript, uv/Poetry/Pipenv lockfiles for Python, Cargo.lock or
cargo for Rust, and go list for Go.  That means real versions -- inherited,
BOM-managed, property-driven, conflict-mediated -- and the transitive graph
that a manifest never names.  Only read-only dependency-inspection commands
are run: never a build, test, install or package step.

Static manifest parsing remains the fallback, and it is never fatal for a
tool to be missing: checkdeps says which tool, why it matters, and how to
install it on the platform it is running on, then scans what it can.

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
    resolver: str | None = None     # id of the resolver that produced this
    introduced_by: str | None = None    # the package that pulled this one in
    scope: str | None = None        # Maven scope / Gradle configuration
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

    # One record per manifest resolved or parsed -- what the presentation
    # layer renders, and what JSON output serialises.
    records: list = field(default_factory=list)

    def merge(self, other: "ParseReport") -> None:
        self.dependencies.extend(other.dependencies)
        self.inactive.extend(other.inactive)
        self.issues.extend(other.issues)
        self.records.extend(other.records)

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
# Platform detection
# ---------------------------------------------------------------------------

# Telling somebody "mvn not found" is not help.  Telling them the one command
# that installs Maven on the machine they are actually sitting at is.  That
# needs three facts: the platform, the package manager present on it, and a
# maintained mapping from tool to package.  Nothing here ever installs
# anything -- checkdeps only explains.


class Platform:
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    OTHER = "other"


PLATFORM_NAMES = {
    Platform.WINDOWS: "Windows",
    Platform.MACOS: "macOS",
    Platform.LINUX: "Linux",
    Platform.OTHER: "this platform",
}


def detect_platform() -> str:
    if sys.platform == "win32":
        return Platform.WINDOWS
    if sys.platform == "darwin":
        return Platform.MACOS
    if sys.platform.startswith("linux"):
        return Platform.LINUX
    return Platform.OTHER


OS_RELEASE_PATH = "/etc/os-release"


def read_os_release(path: str = OS_RELEASE_PATH) -> dict:
    """
    Parse /etc/os-release into a dict, or return {} if it cannot be read.

    Absent or unreadable means the distribution is unknown, and unknown is
    reported as unknown -- never guessed at.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return {}
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def linux_distribution(path: str = OS_RELEASE_PATH) -> tuple:
    """Return (id, [id_like...], pretty name) for the running Linux system."""
    values = read_os_release(path)
    distro_id = (values.get("ID") or "").strip().lower()
    like = [item for item in (values.get("ID_LIKE") or "").lower().split() if item]
    pretty = values.get("PRETTY_NAME") or values.get("NAME") or ""
    return distro_id, like, pretty


# ---------------------------------------------------------------------------
# Package manager detection
# ---------------------------------------------------------------------------

# Installer strategy ids.  These are the keys tools register instructions
# against, so they are part of the registry's contract.
WINGET = "winget"
CHOCO = "choco"
SCOOP = "scoop"
BREW = "brew"
APT = "apt"
DNF = "dnf"
PACMAN = "pacman"
ZYPPER = "zypper"
APK = "apk"


@dataclass
class PackageManager:
    id: str
    display_name: str
    executable: str
    platform: str
    distributions: tuple = ()   # Linux ID / ID_LIKE values this belongs to


PACKAGE_MANAGERS = [
    PackageManager(WINGET, "winget", "winget", Platform.WINDOWS),
    PackageManager(CHOCO, "Chocolatey", "choco", Platform.WINDOWS),
    PackageManager(SCOOP, "Scoop", "scoop", Platform.WINDOWS),
    PackageManager(BREW, "Homebrew", "brew", Platform.MACOS),
    PackageManager(APT, "APT", "apt-get", Platform.LINUX,
                   ("debian", "ubuntu", "linuxmint", "raspbian", "pop")),
    PackageManager(DNF, "DNF", "dnf", Platform.LINUX,
                   ("fedora", "rhel", "centos", "rocky", "almalinux")),
    PackageManager(PACMAN, "pacman", "pacman", Platform.LINUX,
                   ("arch", "manjaro", "endeavouros")),
    PackageManager(ZYPPER, "zypper", "zypper", Platform.LINUX,
                   ("opensuse", "suse", "sles", "opensuse-leap",
                    "opensuse-tumbleweed")),
    PackageManager(APK, "apk", "apk", Platform.LINUX, ("alpine",)),
]

PACKAGE_MANAGERS_BY_ID = {manager.id: manager for manager in PACKAGE_MANAGERS}


def _executable_exists(name: str) -> bool:
    return shutil.which(name) is not None


def detect_package_manager(platform: str | None = None,
                           os_release_path: str = OS_RELEASE_PATH
                           ) -> PackageManager | None:
    """
    The package manager to give instructions for, or None.

    Only managers that are actually installed are ever returned: recommending
    ``brew install`` to somebody without Homebrew is the same dead end as
    recommending nothing.  On Linux the distribution's own manager is
    preferred, and when the distribution cannot be identified checkdeps does
    not guess it -- it simply looks at which manager is on PATH.
    """
    platform = platform or detect_platform()
    candidates = [m for m in PACKAGE_MANAGERS if m.platform == platform]
    if not candidates:
        return None

    if platform == Platform.LINUX:
        distro_id, like, _ = linux_distribution(os_release_path)
        known = [name for name in [distro_id, *like] if name]
        preferred = [
            manager for manager in candidates
            if any(name in manager.distributions for name in known)
        ]
        # Distribution-matched managers first, then any other installed one.
        candidates = preferred + [m for m in candidates if m not in preferred]

    for manager in candidates:
        if _executable_exists(manager.executable):
            return manager
    return None


def describe_platform(platform: str | None = None,
                      os_release_path: str = OS_RELEASE_PATH) -> str:
    """One line naming the platform, including the distribution when known."""
    platform = platform or detect_platform()
    if platform != Platform.LINUX:
        return PLATFORM_NAMES[platform]
    _, _, pretty = linux_distribution(os_release_path)
    return f"Linux: {pretty}" if pretty else "Linux"


# ---------------------------------------------------------------------------
# Tool installation registry
# ---------------------------------------------------------------------------

# Installation commands are user-facing instructions, so they live in one
# maintained table rather than being assembled from package names at the call
# site.  A combination that is not listed here is not guessed at: the tool's
# own installation page is offered instead.


@dataclass
class ToolDefinition:
    id: str
    display_name: str
    executables: tuple            # PATH commands that mean "installed"
    purpose: str                  # why checkdeps wants it, in one sentence
    homepage: str                 # official installation instructions
    installers: dict = field(default_factory=dict)   # installer id -> command
    generic_command: str | None = None   # platform-independent, when there is one

    @property
    def command(self) -> str:
        return self.executables[0] if self.executables else self.id


TOOLS = {
    "maven": ToolDefinition(
        id="maven",
        display_name="Maven",
        executables=("mvn",),
        purpose="resolve the exact versions a pom.xml selects, including "
                "parent-, BOM- and dependencyManagement-supplied versions and "
                "the whole transitive graph",
        homepage="https://maven.apache.org/install.html",
        installers={
            WINGET: "winget install --id Apache.Maven -e",
            CHOCO: "choco install maven",
            SCOOP: "scoop install maven",
            BREW: "brew install maven",
            APT: "sudo apt install maven",
            DNF: "sudo dnf install maven",
            PACMAN: "sudo pacman -S maven",
            ZYPPER: "sudo zypper install maven",
            APK: "sudo apk add maven",
        },
    ),
    "gradle": ToolDefinition(
        id="gradle",
        display_name="Gradle",
        executables=("gradle",),
        purpose="ask Gradle for the dependency graph it resolves, rather than "
                "trying to evaluate build scripts statically",
        homepage="https://gradle.org/install/",
        installers={
            WINGET: "winget install --id Gradle.Gradle -e",
            CHOCO: "choco install gradle",
            SCOOP: "scoop install gradle",
            BREW: "brew install gradle",
            APT: "sudo apt install gradle",
            DNF: "sudo dnf install gradle",
            PACMAN: "sudo pacman -S gradle",
        },
    ),
    "npm": ToolDefinition(
        id="npm",
        display_name="npm",
        executables=("npm",),
        purpose="read the installed dependency tree of a Node.js project",
        homepage="https://nodejs.org/en/download",
        installers={
            WINGET: "winget install --id OpenJS.NodeJS.LTS -e",
            CHOCO: "choco install nodejs-lts",
            SCOOP: "scoop install nodejs-lts",
            BREW: "brew install node",
            APT: "sudo apt install nodejs npm",
            DNF: "sudo dnf install nodejs npm",
            PACMAN: "sudo pacman -S nodejs npm",
            ZYPPER: "sudo zypper install nodejs npm",
            APK: "sudo apk add nodejs npm",
        },
    ),
    "pnpm": ToolDefinition(
        id="pnpm",
        display_name="pnpm",
        executables=("pnpm",),
        purpose="resolve a pnpm workspace, whose pnpm-lock.yaml only pnpm "
                "itself can interpret reliably",
        homepage="https://pnpm.io/installation",
        installers={
            WINGET: "winget install --id pnpm.pnpm -e",
            CHOCO: "choco install pnpm",
            SCOOP: "scoop install pnpm",
            BREW: "brew install pnpm",
        },
        generic_command="npm install -g pnpm",
    ),
    "yarn": ToolDefinition(
        id="yarn",
        display_name="Yarn",
        executables=("yarn",),
        purpose="resolve a Yarn project whose lockfile checkdeps cannot read "
                "on its own",
        homepage="https://yarnpkg.com/getting-started/install",
        installers={
            WINGET: "winget install --id Yarn.Yarn -e",
            CHOCO: "choco install yarn",
            SCOOP: "scoop install yarn",
            BREW: "brew install yarn",
        },
        generic_command="npm install -g yarn",
    ),
    "uv": ToolDefinition(
        id="uv",
        display_name="uv",
        executables=("uv",),
        purpose="produce the uv.lock that pins every version this project "
                "resolves to",
        homepage="https://docs.astral.sh/uv/getting-started/installation/",
        installers={
            WINGET: "winget install --id astral-sh.uv -e",
            CHOCO: "choco install uv",
            SCOOP: "scoop install uv",
            BREW: "brew install uv",
        },
        generic_command="pipx install uv",
    ),
    "poetry": ToolDefinition(
        id="poetry",
        display_name="Poetry",
        executables=("poetry",),
        purpose="produce the poetry.lock that pins every version this project "
                "resolves to",
        homepage="https://python-poetry.org/docs/#installation",
        installers={
            CHOCO: "choco install poetry",
            SCOOP: "scoop install poetry",
            BREW: "brew install poetry",
        },
        generic_command="pipx install poetry",
    ),
    "pipenv": ToolDefinition(
        id="pipenv",
        display_name="Pipenv",
        executables=("pipenv",),
        purpose="produce the Pipfile.lock that pins every version this project "
                "resolves to",
        homepage="https://pipenv.pypa.io/en/latest/installation.html",
        installers={
            BREW: "brew install pipenv",
            APT: "sudo apt install pipenv",
            DNF: "sudo dnf install pipenv",
            PACMAN: "sudo pacman -S python-pipenv",
        },
        generic_command="pipx install pipenv",
    ),
    "cargo": ToolDefinition(
        id="cargo",
        display_name="Cargo",
        executables=("cargo",),
        purpose="read the resolved crate graph of a Rust project",
        homepage="https://www.rust-lang.org/tools/install",
        installers={
            WINGET: "winget install --id Rustlang.Rustup -e",
            CHOCO: "choco install rustup.install",
            SCOOP: "scoop install rustup",
            BREW: "brew install rustup",
            APT: "sudo apt install cargo",
            DNF: "sudo dnf install cargo",
            PACMAN: "sudo pacman -S rust",
        },
    ),
    "go": ToolDefinition(
        id="go",
        display_name="Go",
        executables=("go",),
        purpose="list the module versions Go actually selects, after minimal "
                "version selection and any replace directives",
        homepage="https://go.dev/doc/install",
        installers={
            WINGET: "winget install --id GoLang.Go -e",
            CHOCO: "choco install golang",
            SCOOP: "scoop install go",
            BREW: "brew install go",
            APT: "sudo apt install golang-go",
            DNF: "sudo dnf install golang",
            PACMAN: "sudo pacman -S go",
            ZYPPER: "sudo zypper install go",
            APK: "sudo apk add go",
        },
    ),
}


@dataclass
class InstallAdvice:
    """How to install one tool here: a command, or honest generic guidance."""

    tool: ToolDefinition
    platform: str
    package_manager: PackageManager | None
    command: str | None            # None when nothing confident can be offered
    homepage: str

    @property
    def source(self) -> str:
        if self.command is None:
            return "homepage"
        if self.package_manager and self.tool.installers.get(
                self.package_manager.id) == self.command:
            return self.package_manager.id
        return "generic"


def install_advice(tool_id: str, platform: str | None = None,
                   os_release_path: str = OS_RELEASE_PATH) -> InstallAdvice:
    """Work out the single best installation instruction for this machine."""
    tool = TOOLS[tool_id]
    platform = platform or detect_platform()
    manager = detect_package_manager(platform, os_release_path)

    command = None
    if manager is not None:
        command = tool.installers.get(manager.id)
    if command is None:
        # No registered command for this manager -- a platform-independent one
        # is still better than a guess, and no command at all beats a wrong one.
        command = tool.generic_command
    return InstallAdvice(tool, platform, manager, command, tool.homepage)


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
# Native resolution framework
# ---------------------------------------------------------------------------

# A manifest states intent; the ecosystem's own tooling states what was
# actually selected.  Every ecosystem therefore registers a profile with an
# ordered list of resolvers, and each resolver answers one question: "can you
# produce the resolved graph for this project right now?"  When none can, the
# static parser still runs -- an absent tool degrades the answer, it never
# fails the scan.


class ToolErrorKind:
    """Why a resolver could not produce a graph.  Never collapsed into one."""

    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    TOOL_VERSION_TOO_OLD = "TOOL_VERSION_TOO_OLD"
    TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED"
    RESOLUTION_FAILED = "RESOLUTION_FAILED"
    OUTPUT_INVALID = "OUTPUT_INVALID"
    TIMEOUT = "TIMEOUT"


DEFAULT_RESOLVER_TIMEOUT = 300     # seconds, per resolver invocation


@dataclass
class MissingTool:
    """
    A tool checkdeps wanted and could not use.

    Deliberately data, not a message: resolvers never print.  The presentation
    layer turns this into platform-aware help, and JSON output serialises the
    same record.
    """

    tool_id: str
    command: str
    resolver: str
    project: str
    required_for: str
    fallback: str                       # what checkdeps did instead
    kind: str = ToolErrorKind.TOOL_NOT_FOUND
    found_version: str | None = None
    required_version: str | None = None
    next_step: str | None = None        # a project command to run once installed

    @property
    def tool(self) -> ToolDefinition:
        return TOOLS[self.tool_id]


@dataclass
class ToolCommand:
    argv: list           # executable plus fixed arguments -- never a shell string
    display: str         # what to show the user
    source: str          # "wrapper" | "path"
    version: str | None = None


@dataclass
class Resolution:
    """The outcome of one resolver attempt."""

    dependencies: list = field(default_factory=list)
    resolver_id: str = ""
    resolver_label: str = ""
    command: ToolCommand | None = None
    error: str | None = None       # a ToolErrorKind value when it went wrong
    reason: str | None = None      # one concise line explaining the failure
    output: str = ""               # captured tool log, shown only with --verbose
    missing_tool: MissingTool | None = None
    diagnostics: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


def find_project_wrapper(project_dir: Path, names) -> Path | None:
    """
    Look for a project-local wrapper script, searching upwards.

    A wrapper pins the tool version the project itself expects, so it beats
    whatever is on PATH.  The search walks up because multi-module builds keep
    one wrapper at the reactor/root project, not beside every module.
    """
    if not names:
        return None
    try:
        directory = project_dir.resolve()
    except OSError:
        directory = project_dir
    for parent in [directory, *directory.parents]:
        for name in names:
            candidate = parent / name
            if candidate.is_file():
                return candidate
    return None


def run_tool(argv: list, cwd: Path, timeout: int,
             environment: dict | None = None) -> tuple:
    """
    Run an external tool safely and classify anything that goes wrong.

    Returns ``(process, error_kind, reason)`` with exactly one of ``process``
    or ``error_kind`` set.  Arguments are always a list -- never a shell
    string -- so paths containing spaces need no quoting and nothing the
    project controls can be interpreted as a command.
    """
    child_environment = None
    if environment:
        child_environment = {**os.environ, **environment}
    try:
        process = subprocess.run(
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env=child_environment,
        )
    except subprocess.TimeoutExpired:
        return None, ToolErrorKind.TIMEOUT, f"no result within {timeout}s"
    except OSError as exc:
        # A wrapper that will not start says nothing about the project, so this
        # is reported as an absent tool rather than a broken project.
        return None, ToolErrorKind.TOOL_NOT_FOUND, f"could not start {argv[0]}: {exc}"
    return process, None, None


def tool_version(command: ToolCommand, argument: str = "--version",
                 timeout: int = 60) -> str | None:
    """The tool's own version string, or None if it will not report one."""
    process, error, _ = run_tool([*command.argv, argument], Path.cwd(), timeout)
    if error is not None or process.returncode != 0:
        return None
    for line in ((process.stdout or "") + (process.stderr or "")).splitlines():
        line = line.strip()
        if line:
            return line
    return None


def version_at_least(found: str | None, minimum: str) -> bool | None:
    """
    Compare two tool version strings, or None when ``found`` is unreadable.

    Unreadable is not "too old": a tool that reports its version in some shape
    checkdeps does not know still gets its chance to run.
    """
    if not found:
        return None
    match = re.search(r"(\d+(?:\.\d+)*)", found)
    if match is None:
        return None
    try:
        return Version(match.group(1)) >= Version(minimum)
    except InvalidVersion:
        return None


# Diagnostics quote whatever a build tool printed, and build tools print
# repository URLs.  Anything shaped like a credential is masked before it can
# reach a terminal, a log or a CI transcript.
_CREDENTIAL_PATTERNS = [
    (re.compile(r"(?P<scheme>[a-zA-Z][\w+.-]*://)[^/\s:@]+:[^/\s@]+@"),
     r"\g<scheme>***:***@"),
    # No leading \b: a secret is just as secret in -Dpassword=... as on its own.
    (re.compile(r"(?i)(authorization|token|password|passwd|secret|"
                r"api[_-]?key)\b(\s*[:=]\s*|\s+)(?:bearer\s+|basic\s+)?\S+"),
     r"\1\2***"),
    (re.compile(r"(?i)\bbearer\s+\S+"), "Bearer ***"),
]


def redact_secrets(text: str) -> str:
    """Mask credentials in anything a tool printed before it is displayed."""
    for pattern, replacement in _CREDENTIAL_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def json_objects(text: str) -> list:
    """
    Decode a stream of concatenated JSON objects.

    Several tools emit one object per project/module rather than a single
    document -- Maven with appendOutput, ``go list -json``, Yarn's NDJSON.
    """
    decoder = json.JSONDecoder()
    objects: list = []
    index, length = 0, len(text)
    while index < length:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        try:
            obj, index = decoder.raw_decode(text, index)
        except ValueError as exc:
            raise ValueError("tool output was not valid JSON") from exc
        objects.append(obj)
    if not objects:
        raise ValueError("tool produced no output to parse")
    return objects


@dataclass
class ResolutionContext:
    """Everything a resolver may look at before deciding it can run."""

    profile: "ResolverProfile"
    project_dir: Path
    files: dict                       # filename -> Path, for this project only
    options: "ScanOptions"

    def path(self, name: str) -> Path | None:
        return self.files.get(name)

    def has(self, *names) -> bool:
        return any(name in self.files for name in names)

    @property
    def timeout(self) -> int:
        return self.options.resolver_timeout


class Resolver:
    """
    One way to obtain a resolved dependency graph.

    Subclasses implement :meth:`triggers` (is this resolver relevant to the
    project at hand?) and :meth:`resolve`.  Those that drive an external
    executable declare ``tool_id`` so a missing one produces installation help
    instead of a shrug.
    """

    id = ""
    label = ""
    tool_id: str | None = None
    executables: tuple = ()
    windows_wrappers: tuple = ()
    posix_wrappers: tuple = ()
    minimum_version: str | None = None
    version_argument = "--version"
    supersedes: tuple = ()             # manifests this replaces when it succeeds
    required_for = "the resolved dependency graph"
    next_step: str | None = None       # command that would make this work

    @property
    def needs_tool(self) -> bool:
        return self.tool_id is not None

    def triggers(self, ctx: ResolutionContext) -> bool:
        raise NotImplementedError

    def priority(self, ctx: ResolutionContext) -> int:
        """Lower runs first.  Override to honour a project's own choice."""
        return 0

    def wrapper_names(self) -> tuple:
        return self.windows_wrappers if os.name == "nt" else self.posix_wrappers

    def find_command(self, ctx: ResolutionContext) -> ToolCommand | None:
        """The executable to drive, wrapper first, or None if there is none."""
        wrapper = find_project_wrapper(ctx.project_dir, self.wrapper_names())
        if wrapper is not None:
            return ToolCommand([str(wrapper)], str(wrapper), "wrapper")
        return self.command_on_path()

    def command_on_path(self) -> ToolCommand | None:
        for executable in self.executables:
            found = shutil.which(executable)
            if found:
                return ToolCommand([found], found, "path")
        return None

    def describe(self, command: ToolCommand | None) -> str:
        if command is not None and command.source == "wrapper":
            return f"{self.label} Wrapper"
        return self.label

    def missing(self, ctx: ResolutionContext, fallback: str,
                kind: str = ToolErrorKind.TOOL_NOT_FOUND,
                found_version: str | None = None) -> MissingTool:
        return MissingTool(
            tool_id=self.tool_id,
            command=TOOLS[self.tool_id].command,
            resolver=self.id,
            project=str(ctx.profile.primary_target(ctx)),
            required_for=self.required_for,
            fallback=fallback,
            kind=kind,
            found_version=found_version,
            required_version=self.minimum_version,
            next_step=self.next_step,
        )

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        raise NotImplementedError


class LockfileResolver(Resolver):
    """A resolver that reads a lockfile the project already contains."""

    lockfiles: tuple = ()

    def triggers(self, ctx: ResolutionContext) -> bool:
        return ctx.has(*self.lockfiles)

    def find_command(self, ctx: ResolutionContext) -> ToolCommand | None:
        return None

    def lockfile(self, ctx: ResolutionContext) -> Path | None:
        for name in self.lockfiles:
            found = ctx.path(name)
            if found is not None:
                return found
        return None

    def describe(self, command: ToolCommand | None) -> str:
        return self.label


def failed(resolver: Resolver, kind: str, reason: str,
           command: ToolCommand | None = None, output: str = "") -> Resolution:
    return Resolution(
        resolver_id=resolver.id,
        resolver_label=resolver.describe(command),
        command=command,
        error=kind,
        reason=reason,
        output=output,
    )


def resolved(resolver: Resolver, dependencies: list,
             command: ToolCommand | None = None, output: str = "",
             diagnostics: list | None = None) -> Resolution:
    return Resolution(
        dependencies=dependencies,
        resolver_id=resolver.id,
        resolver_label=resolver.describe(command),
        command=command,
        output=output,
        diagnostics=diagnostics or [],
    )



# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

# Maven -- not the raw pom.xml -- decides which artifacts a project uses:
# parents, dependencyManagement, imported BOMs, ${properties} and conflict
# mediation all live inside Maven's model.

MAVEN_DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin"
# Pinned so the JSON output type is guaranteed to exist regardless of which
# plugin version the project itself would otherwise select.
MAVEN_DEPENDENCY_PLUGIN_VERSION = "3.8.1"

MAVEN_SCOPES = {"compile", "provided", "runtime", "test", "system", "import"}
# Scopes checkdeps treats as dev, matching what the static POM parser does.
MAVEN_DEV_SCOPES = {"test", "provided"}


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


def _dependencies_from_tree(tree, source: str, into: dict,
                            resolver_id: str = "maven") -> None:
    """
    Walk one module's tree, adding its dependencies to ``into``.

    The root node is the module itself and is skipped; its children are the
    declared (direct) dependencies and everything below them is transitive.
    Maven reports an artifact once per path that reaches it, so the first
    record wins -- but reaching it directly later still promotes it.
    """
    if not isinstance(tree, dict):
        return

    def walk(node, direct: bool, parent: str | None) -> None:
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
            resolution="native",
            resolver=resolver_id,
            introduced_by=parent,
            scope=coords["scope"],
            direct=direct,
            artifact_type=coords["type"],
            classifier=coords["classifier"],
        )
        for child in node.get("children") or []:
            walk(child, False, name)

    for child in tree.get("children") or []:
        walk(child, True, None)


def _classify_maven_failure(output: str) -> tuple:
    """Map a failed Maven run onto (ToolErrorKind, one-line reason)."""
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
        return ToolErrorKind.RESOLUTION_FAILED, resolution_hit

    plugin_hit = first_matching("plugin org.apache.maven.plugins", "no plugin found")
    if plugin_hit:
        return ToolErrorKind.TOOL_EXECUTION_FAILED, plugin_hit

    reason = ""
    for line in errors:
        reason = re.sub(r"^\[(ERROR|FATAL)\]\s*", "", line).strip()
        if reason:
            break
    return ToolErrorKind.TOOL_EXECUTION_FAILED, reason or "Maven exited with an error"


class MavenResolver(Resolver):
    """
    Ask Maven for the dependency graph of a pom.xml.

    Runs a single dependency-inspection goal -- never a lifecycle phase such as
    package, install, verify or test -- with the pom's own directory as the
    working directory, so the project's settings.xml, mirrors, credentials and
    local repository apply exactly as they would to a normal build.
    """

    id = "maven"
    label = "Maven"
    tool_id = "maven"
    executables = ("mvn",)
    windows_wrappers = ("mvnw.cmd", "mvnw.bat")
    posix_wrappers = ("mvnw",)
    supersedes = ("pom.xml",)
    required_for = "the resolved Maven dependency graph"

    def triggers(self, ctx: ResolutionContext) -> bool:
        return ctx.has("pom.xml")

    def command_line(self, pom: Path, output_file: Path,
                     command: ToolCommand) -> list:
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

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        pom = ctx.path("pom.xml")
        handle, temp_name = tempfile.mkstemp(prefix="checkdeps-maven-",
                                             suffix=".json")
        os.close(handle)
        output_file = Path(temp_name)
        try:
            argv = self.command_line(pom, output_file, command)
            process, error, reason = run_tool(argv, ctx.project_dir, ctx.timeout)
            if error is not None:
                return failed(self, error, reason, command)

            output = (process.stdout or "") + (process.stderr or "")
            if process.returncode != 0:
                kind, why = _classify_maven_failure(output)
                return failed(self, kind, why, command, output)

            try:
                raw = output_file.read_text(encoding="utf-8")
            except OSError as exc:
                return failed(self, ToolErrorKind.OUTPUT_INVALID,
                              f"Maven wrote no dependency tree ({exc})",
                              command, output)
            try:
                trees = json_objects(raw)
            except ValueError as exc:
                return failed(self, ToolErrorKind.OUTPUT_INVALID, str(exc),
                              command, output)

            collected: dict = {}
            for tree in trees:
                _dependencies_from_tree(tree, str(pom), collected, self.id)
            return resolved(self, list(collected.values()), command, output,
                            [f"resolution command: {' '.join(argv)}"])
        finally:
            # Both paths, always: nothing generated is left in the temp
            # directory, and nothing is ever written into the scanned project.
            try:
                output_file.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Gradle
# ---------------------------------------------------------------------------

# Gradle build scripts are programs, so checkdeps does not try to evaluate
# them: it asks Gradle for the graph it resolves and reads the report.

# Configurations worth scanning.  Anything ending in "Classpath" is what
# actually reaches the application or its tests; the legacy names cover older
# builds that never migrated.
GRADLE_LEGACY_CONFIGURATIONS = {"compile", "runtime", "default"}

GRADLE_COORDINATE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]*$")

# The configurations a static read of build.gradle understands, and whether
# each one only matters to tests.
GRADLE_STATIC_CONFIGURATIONS = {
    "implementation": False,
    "api": False,
    "compileOnly": False,
    "compileOnlyApi": False,
    "runtimeOnly": False,
    "developmentOnly": False,
    "annotationProcessor": False,
    "kapt": False,
    "ksp": False,
    "compile": False,
    "runtime": False,
    "testImplementation": True,
    "testCompileOnly": True,
    "testRuntimeOnly": True,
    "testAnnotationProcessor": True,
    "testCompile": True,
    "testRuntime": True,
    "androidTestImplementation": True,
}


def gradle_configuration_is_dev(name: str) -> bool:
    return name.lower().startswith(("test", "androidtest"))


def gradle_configuration_is_scanned(name: str) -> bool:
    return name.endswith("Classpath") or name in GRADLE_LEGACY_CONFIGURATIONS


def _gradle_tree_entry(line: str) -> tuple | None:
    """
    Split one line of a Gradle dependency report into (depth, entry).

    The report draws its tree in fixed five-character columns, so depth is
    counted rather than guessed from leading whitespace.
    """
    rest = line.rstrip()
    depth = 0
    while True:
        head = rest[:5]
        if head in ("|    ", "     "):
            rest = rest[5:]
            depth += 1
            continue
        if head in ("+--- ", "\\--- "):
            return depth + 1, rest[5:].strip()
        return None


def _gradle_selected_version(entry: str) -> tuple | None:
    """
    Read ``group:artifact:version`` out of one report entry.

    Handles the report's own notations: ``requested -> selected`` for conflict
    resolution, and the trailing markers for omitted subtrees.  Entries Gradle
    itself could not resolve are dropped rather than reported at their
    requested version.
    """
    text = entry.strip()
    unresolved = False
    while text.endswith((" (*)", " (n)", " (c)", " (+)")):
        unresolved = unresolved or text.endswith(" (n)")
        text = text[:-4].rstrip()
    if not text or text.startswith("project ") or text.startswith("--- "):
        return None
    if unresolved:
        return None

    requested, arrow, selected = text.partition(" -> ")
    parts = requested.split(":")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    group, artifact = parts[0].strip(), parts[1].strip()
    version = selected.strip() if arrow else (parts[2].strip() if len(parts) > 2 else "")
    if not GRADLE_COORDINATE.match(version or ""):
        return None
    return group, artifact, version


def parse_gradle_report(text: str, source: str, resolver_id: str) -> list:
    """Turn a ``gradle dependencies`` report into normalised dependencies."""
    collected: dict = {}
    configuration = None
    stack: dict = {}
    for line in text.splitlines():
        entry = _gradle_tree_entry(line)
        if entry is None:
            stripped = line.strip()
            header = re.match(r"^([A-Za-z][A-Za-z0-9_]*)(?: - .*)?$", stripped)
            if header and not line.startswith(" "):
                configuration = header.group(1)
                stack = {}
            continue
        if configuration is None or not gradle_configuration_is_scanned(configuration):
            continue

        depth, body = entry
        coordinates = _gradle_selected_version(body)
        if coordinates is None:
            stack.pop(depth, None)
            continue
        group, artifact, version = coordinates
        name = f"{group}:{artifact}"
        stack[depth] = name
        for deeper in [key for key in stack if key > depth]:
            del stack[deeper]

        is_dev = gradle_configuration_is_dev(configuration)
        key = (name, version)
        existing = collected.get(key)
        if existing is not None:
            existing.direct = existing.direct or depth == 1
            existing.is_dev = existing.is_dev and is_dev
            continue
        collected[key] = Dependency(
            name=name,
            version=version,
            ecosystem="Maven",
            source_file=source,
            is_dev=is_dev,
            resolution="native",
            resolver=resolver_id,
            introduced_by=stack.get(depth - 1),
            scope=configuration,
            direct=depth == 1,
        )
    return list(collected.values())


class GradleResolver(Resolver):
    """
    Ask Gradle for its resolved dependency report.

    Only the read-only ``dependencies`` task is run: no build, no tests, no
    artifacts.  The wrapper is preferred because it pins the Gradle version
    the build was written for.
    """

    id = "gradle"
    label = "Gradle"
    tool_id = "gradle"
    executables = ("gradle",)
    windows_wrappers = ("gradlew.bat",)
    posix_wrappers = ("gradlew",)
    supersedes = ("build.gradle", "build.gradle.kts")
    required_for = "the resolved Gradle dependency graph"

    def triggers(self, ctx: ResolutionContext) -> bool:
        return ctx.has("build.gradle", "build.gradle.kts")

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        build_file = ctx.path("build.gradle") or ctx.path("build.gradle.kts")
        argv = [
            *command.argv,
            "--console=plain",
            "--quiet",
            # No daemon: a scan should not leave a background process behind
            # on a machine that was not already running Gradle builds.
            "--no-daemon",
        ]
        if ctx.options.offline:
            argv.append("--offline")
        argv.append("dependencies")
        process, error, reason = run_tool(argv, ctx.project_dir, ctx.timeout)
        if error is not None:
            return failed(self, error, reason, command)

        output = (process.stdout or "") + (process.stderr or "")
        if process.returncode != 0:
            return failed(self, ToolErrorKind.RESOLUTION_FAILED,
                          _first_error_line(output, "Gradle exited with an error"),
                          command, output)

        dependencies = parse_gradle_report(process.stdout or "", str(build_file),
                                           self.id)
        if not dependencies:
            # Gradle can report success while every classpath it printed
            # failed to resolve.  Nothing resolved is not an answer, so the
            # static reading of the build script gets its turn instead.
            reason = ("Gradle resolved no dependencies"
                      + (" (the report contains FAILED entries)"
                         if "FAILED" in output else ""))
            return failed(self, ToolErrorKind.RESOLUTION_FAILED, reason,
                          command, output)
        return resolved(self, dependencies, command, output,
                        [f"resolution command: {' '.join(argv)}"])


def _first_error_line(output: str, default: str) -> str:
    """The most useful single line out of a failed tool's output."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in lines:
        lowered = line.lower()
        if lowered.startswith(("error:", "fatal:", "* what went wrong")):
            return line
    for index, line in enumerate(lines):
        if line.lower().startswith("* what went wrong") and index + 1 < len(lines):
            return lines[index + 1]
    for line in lines:
        if "error" in line.lower() or "could not" in line.lower():
            return line
    return lines[-1] if lines else default


def parse_build_gradle(path: Path) -> ParseReport:
    """
    Read declared dependencies out of a Gradle build script.

    A fallback only: build scripts are code, so anything computed at build
    time -- a version property, a platform BOM, a plugin-managed version --
    stays unresolved here.  Gradle itself is what resolves those.
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as exc:
        return _read_error(path, exc)

    report = ParseReport()
    seen = set()

    def add(configuration: str, group: str, artifact: str, version, raw: str,
            lineno: int) -> None:
        if configuration not in GRADLE_STATIC_CONFIGURATIONS:
            return
        name = f"{group}:{artifact}"
        if (name, version) in seen:
            return
        seen.add((name, version))
        report.dependencies.append(Dependency(
            name=name,
            version=version,
            ecosystem="Maven",
            source_file=str(path),
            is_dev=GRADLE_STATIC_CONFIGURATIONS[configuration],
            specifier=version,
            resolution="manifest" if version else None,
            scope=configuration,
            line=lineno,
            raw=raw,
        ))

    string_notation = re.compile(
        r"""(?P<configuration>[A-Za-z][A-Za-z0-9]*)\s*[(\s]\s*
            (?P<quote>['"])(?P<coordinate>[^'"]+)(?P=quote)""",
        re.VERBOSE,
    )
    map_notation = re.compile(
        r"""(?P<configuration>[A-Za-z][A-Za-z0-9]*)\s*[(\s]\s*
            group:\s*['"](?P<group>[^'"]+)['"]\s*,\s*
            name:\s*['"](?P<artifact>[^'"]+)['"]
            (?:\s*,\s*version:\s*['"](?P<version>[^'"]+)['"])?""",
        re.VERBOSE,
    )

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//")[0]
        match = map_notation.search(line)
        if match:
            add(match.group("configuration"), match.group("group"),
                match.group("artifact"), match.group("version"), raw.strip(), lineno)
            continue
        match = string_notation.search(line)
        if not match:
            continue
        parts = match.group("coordinate").split(":")
        if len(parts) < 2 or "$" in parts[0] or "$" in parts[1]:
            continue          # an interpolated coordinate names no package
        version = parts[2].strip() if len(parts) > 2 else None
        if version and not GRADLE_COORDINATE.match(version):
            version = None
        add(match.group("configuration"), parts[0].strip(), parts[1].strip(),
            version or None, raw.strip(), lineno)
    return report



# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------

# package.json records ranges; the lockfile records what those ranges resolved
# to, for the whole tree.  npm and Yarn lockfiles are deterministic formats
# that checkdeps reads directly, so no tool has to be installed.  pnpm's
# lockfile is pnpm's own business, so pnpm itself is asked.

NPM_DEPENDENCY_SECTIONS = [
    ("dependencies", False),
    ("devDependencies", True),
    ("optionalDependencies", False),
    ("peerDependencies", False),
]


def read_package_json(path: Path | None) -> dict:
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def package_json_declarations(path: Path | None) -> tuple:
    """Return (direct names, dev-only names) as declared in package.json."""
    data = read_package_json(path)
    direct, dev_only = set(), set()
    for section, is_dev in NPM_DEPENDENCY_SECTIONS:
        names = data.get(section)
        if not isinstance(names, dict):
            continue
        for name in names:
            direct.add(name)
            if is_dev:
                dev_only.add(name)
    return direct, dev_only - (direct - dev_only)


def declared_package_manager(path: Path | None) -> str | None:
    """The ``packageManager`` field's tool name, e.g. "pnpm" -- or None."""
    field_value = read_package_json(path).get("packageManager")
    if not isinstance(field_value, str) or not field_value.strip():
        return None
    return field_value.strip().split("@")[0].lower() or None


def _npm_dependency(name: str, version: str, source: str, resolver_id: str,
                    *, direct: bool, is_dev: bool,
                    introduced_by: str | None = None) -> Dependency:
    return Dependency(
        name=name,
        version=version,
        ecosystem="npm",
        source_file=source,
        is_dev=is_dev,
        resolution="native",
        resolver=resolver_id,
        introduced_by=introduced_by,
        direct=direct,
    )


def _merge_dependency(into: dict, dependency: Dependency) -> None:
    key = (dependency.name, dependency.version)
    existing = into.get(key)
    if existing is None:
        into[key] = dependency
        return
    existing.direct = existing.direct or dependency.direct
    existing.is_dev = existing.is_dev and dependency.is_dev


def walk_npm_tree(node: dict, source: str, resolver_id: str, into: dict,
                  *, direct: bool = True, is_dev: bool = False,
                  parent: str | None = None, depth: int = 0) -> None:
    """
    Walk the nested ``{name: {version, dependencies: {...}}}`` shape.

    ``npm ls --json`` and ``pnpm ls --json`` both produce it, so one walker
    serves both.  Entries npm marks missing or unmet have no version and are
    skipped rather than reported at a guessed one.
    """
    if not isinstance(node, dict) or depth > 64:
        return
    for name, entry in node.items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            continue
        dev = bool(entry.get("dev")) or is_dev
        _merge_dependency(into, _npm_dependency(
            name, version, source, resolver_id,
            direct=direct, is_dev=dev, introduced_by=parent,
        ))
        walk_npm_tree(entry.get("dependencies") or {}, source, resolver_id, into,
                      direct=False, is_dev=dev, parent=name, depth=depth + 1)


class NpmLockResolver(LockfileResolver):
    """Read package-lock.json / npm-shrinkwrap.json, every version pinned."""

    id = "npm-lock"
    label = "package-lock.json"
    lockfiles = ("package-lock.json", "npm-shrinkwrap.json")
    supersedes = ("package.json",)

    def priority(self, ctx: ResolutionContext) -> int:
        return -1 if declared_package_manager(ctx.path("package.json")) == "npm" else 0

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        lock = self.lockfile(ctx)
        try:
            data = json.loads(lock.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"could not read {lock.name}: {exc}")
        if not isinstance(data, dict):
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"{lock.name} is not a lockfile object")

        direct_names, dev_names = package_json_declarations(ctx.path("package.json"))
        source = str(lock)
        collected: dict = {}

        packages = data.get("packages")
        if isinstance(packages, dict) and packages:
            # Lockfile v2/v3: one flat entry per installed path.
            root = packages.get("") or {}
            if isinstance(root, dict):
                for section, _ in NPM_DEPENDENCY_SECTIONS:
                    names = root.get(section)
                    if isinstance(names, dict):
                        direct_names.update(names)
            for location, entry in packages.items():
                if not location or not isinstance(entry, dict):
                    continue
                if entry.get("link") or "node_modules/" not in location:
                    continue          # workspace symlinks are not packages
                version = entry.get("version")
                if not isinstance(version, str) or not version:
                    continue
                name = location.rsplit("node_modules/", 1)[1]
                _merge_dependency(collected, _npm_dependency(
                    name, version, source, self.id,
                    direct=name in direct_names,
                    is_dev=bool(entry.get("dev") or entry.get("devOptional"))
                    or name in dev_names,
                ))
        else:
            # Lockfile v1: a nested tree under "dependencies".
            walk_npm_tree(data.get("dependencies") or {}, source, self.id,
                          collected)
            for dependency in collected.values():
                dependency.direct = dependency.name in direct_names
                dependency.is_dev = dependency.is_dev or dependency.name in dev_names

        if not collected:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"{lock.name} listed no resolved packages")
        return resolved(self, list(collected.values()))


# Yarn's classic and Berry lockfiles are different formats that happen to look
# alike; the entry key says which protocol an entry uses, and only npm-hosted
# packages have versions OSV can be asked about.
YARN_DESCRIPTOR = re.compile(r"^(?P<name>@?[^@\s]+(?:/[^@\s]+)?)@(?P<range>.*)$")
YARN_NPM_PROTOCOLS = ("npm:", "")
YARN_SKIPPED_PROTOCOLS = ("workspace:", "patch:", "link:", "portal:", "file:",
                          "exec:", "git:", "github:", "http:", "https:")


def parse_yarn_lock(text: str) -> list:
    """
    Read (name, version) pairs out of either Yarn lockfile generation.

    Classic writes ``version "1.2.3"``, Berry writes ``version: 1.2.3``; both
    key their entries on comma-separated descriptors.  Berry's ``__metadata``
    block carries a version field of its own and is skipped explicitly.
    """
    entries = []
    descriptors: list = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            if not line.endswith(":"):
                descriptors = []
                continue
            descriptors = [
                part.strip().strip('"').strip("'")
                for part in line[:-1].split(",")
            ]
            continue
        if not descriptors:
            continue
        stripped = line.strip()
        match = re.match(r'^version:?\s+"?([^"\s]+)"?$', stripped)
        if not match:
            continue
        version = match.group(1)
        for descriptor in descriptors:
            if descriptor == "__metadata":
                continue
            parsed = YARN_DESCRIPTOR.match(descriptor)
            if parsed is None:
                continue
            protocol = parsed.group("range")
            if protocol.startswith(YARN_SKIPPED_PROTOCOLS):
                continue
            name = parsed.group("name")
            if name:
                entries.append((name, version))
        descriptors = []
    return entries


class YarnLockResolver(LockfileResolver):
    """Read yarn.lock, classic or Berry."""

    id = "yarn-lock"
    label = "yarn.lock"
    lockfiles = ("yarn.lock",)
    supersedes = ("package.json",)

    def priority(self, ctx: ResolutionContext) -> int:
        return -1 if declared_package_manager(ctx.path("package.json")) == "yarn" else 0

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        lock = self.lockfile(ctx)
        try:
            text = lock.read_text(encoding="utf-8-sig")
        except OSError as exc:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"could not read {lock.name}: {exc}")

        direct_names, dev_names = package_json_declarations(ctx.path("package.json"))
        source = str(lock)
        collected: dict = {}
        for name, version in parse_yarn_lock(text):
            _merge_dependency(collected, _npm_dependency(
                name, version, source, self.id,
                direct=name in direct_names,
                is_dev=name in dev_names,
            ))
        if not collected:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          "yarn.lock listed no resolved packages")
        return resolved(self, list(collected.values()))


class PnpmResolver(Resolver):
    """
    Ask pnpm for the tree it installed.

    pnpm-lock.yaml is pnpm's own format and changes between majors, so pnpm is
    asked instead of parsed.  ``pnpm ls`` only reads what is on disk -- it
    installs nothing.
    """

    id = "pnpm"
    label = "pnpm"
    tool_id = "pnpm"
    executables = ("pnpm",)
    minimum_version = "7"
    supersedes = ("package.json",)
    required_for = "the resolved pnpm dependency graph"
    next_step = "pnpm install"

    def triggers(self, ctx: ResolutionContext) -> bool:
        return (ctx.has("pnpm-lock.yaml")
                or declared_package_manager(ctx.path("package.json")) == "pnpm")

    def priority(self, ctx: ResolutionContext) -> int:
        return -1 if declared_package_manager(ctx.path("package.json")) == "pnpm" else 0

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        argv = [*command.argv, "ls", "--depth", "Infinity", "--json"]
        process, error, reason = run_tool(argv, ctx.project_dir, ctx.timeout)
        if error is not None:
            return failed(self, error, reason, command)
        output = (process.stdout or "") + (process.stderr or "")
        if process.returncode != 0:
            return failed(self, ToolErrorKind.RESOLUTION_FAILED,
                          _first_error_line(output, "pnpm exited with an error"),
                          command, output)
        try:
            projects = json.loads(process.stdout or "[]")
        except ValueError as exc:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"pnpm did not return JSON ({exc})", command, output)

        source = str(ctx.path("package.json") or ctx.path("pnpm-lock.yaml"))
        collected: dict = {}
        for project in projects if isinstance(projects, list) else [projects]:
            if not isinstance(project, dict):
                continue
            for section, is_dev in NPM_DEPENDENCY_SECTIONS:
                walk_npm_tree(project.get(section) or {}, source, self.id,
                              collected, is_dev=is_dev)
        if not collected:
            return failed(
                self, ToolErrorKind.RESOLUTION_FAILED,
                "pnpm reported no installed packages -- run 'pnpm install' first",
                command, output,
            )
        return resolved(self, list(collected.values()), command, output,
                        [f"resolution command: {' '.join(argv)}"])


class NpmTreeResolver(Resolver):
    """
    Ask npm for the tree it installed.

    Only useful once ``npm install`` has run, so it sits behind the lockfile
    resolvers, which need nothing on disk but the lockfile itself.
    """

    id = "npm"
    label = "npm"
    tool_id = "npm"
    executables = ("npm",)
    supersedes = ("package.json",)
    required_for = "the installed npm dependency tree"
    next_step = "npm install"

    def triggers(self, ctx: ResolutionContext) -> bool:
        return (ctx.project_dir / "node_modules").is_dir()

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        argv = [*command.argv, "ls", "--all", "--json"]
        process, error, reason = run_tool(argv, ctx.project_dir, ctx.timeout)
        if error is not None:
            return failed(self, error, reason, command)
        output = (process.stdout or "") + (process.stderr or "")
        try:
            # npm exits non-zero for peer/extraneous complaints while still
            # printing a complete tree, so the JSON is read before judging.
            data = json.loads(process.stdout or "")
        except ValueError:
            return failed(self, ToolErrorKind.RESOLUTION_FAILED,
                          _first_error_line(output, "npm exited with an error"),
                          command, output)

        source = str(ctx.path("package.json"))
        collected: dict = {}
        walk_npm_tree(data.get("dependencies") or {}, source, self.id, collected)
        if not collected:
            return failed(self, ToolErrorKind.RESOLUTION_FAILED,
                          "npm reported no installed packages", command, output)
        return resolved(self, list(collected.values()), command, output,
                        [f"resolution command: {' '.join(argv)}"])



# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

# Python's resolvers write their answer down: uv.lock, poetry.lock and
# Pipfile.lock each pin the exact version of every package in the graph,
# transitive ones included.  Reading them beats running anything -- it needs
# no tool installed, touches no environment, and installs nothing, which is
# the one thing a scanner must never do to the project it is scanning.


def _load_toml(path: Path):
    import tomllib
    return tomllib.loads(path.read_text(encoding="utf-8-sig"))


def _python_dependency(name: str, version: str, source: str, resolver_id: str,
                       *, direct: bool, is_dev: bool) -> Dependency:
    return Dependency(
        name=canonicalize_name(name),
        version=version,
        ecosystem="PyPI",
        source_file=source,
        is_dev=is_dev,
        resolution="lockfile",
        resolver=resolver_id,
        direct=direct,
    )


def _names_from(value) -> set:
    """Collect package names from the several shapes lock tables use."""
    names = set()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                names.add(canonicalize_name(item))
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                names.add(canonicalize_name(item["name"]))
    elif isinstance(value, dict):
        for key, nested in value.items():
            if key in ("dependencies", "extras"):
                names |= _names_from(nested)
            elif isinstance(nested, (list, dict)):
                names |= _names_from(nested)
            elif isinstance(key, str):
                names.add(canonicalize_name(key))
    return names


class UvLockResolver(LockfileResolver):
    """Read uv.lock: every package uv selected, with its exact version."""

    id = "uv-lock"
    label = "uv.lock"
    lockfiles = ("uv.lock",)
    supersedes = ("pyproject.toml",)

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        lock = self.lockfile(ctx)
        try:
            data = _load_toml(lock)
        except Exception as exc:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"could not read uv.lock: {exc}")

        packages = data.get("package")
        if not isinstance(packages, list) or not packages:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          "uv.lock listed no packages")

        direct, dev = set(), set()
        roots = set()
        for package in packages:
            if not isinstance(package, dict):
                continue
            source = package.get("source")
            # The project itself is locked as a package with a local source.
            if isinstance(source, dict) and ({"virtual", "editable"} & set(source)):
                roots.add(canonicalize_name(str(package.get("name") or "")))
                direct |= _names_from(package.get("dependencies"))
                direct |= _names_from(package.get("optional-dependencies"))
                dev |= _names_from(package.get("dev-dependencies"))

        collected = []
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = str(package.get("name") or "")
            version = str(package.get("version") or "")
            if not name or not version:
                continue
            canonical = canonicalize_name(name)
            if canonical in roots:
                continue
            collected.append(_python_dependency(
                name, version, str(lock), self.id,
                direct=canonical in direct or canonical in dev,
                is_dev=canonical in dev and canonical not in direct,
            ))
        if not collected:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          "uv.lock contained no resolved packages")
        return resolved(self, collected)


def poetry_declarations(pyproject: Path | None) -> tuple:
    """Direct and dev-only package names declared for Poetry."""
    if pyproject is None:
        return set(), set()
    try:
        data = _load_toml(pyproject)
    except Exception:
        return set(), set()
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    direct = {
        canonicalize_name(name)
        for name in (poetry.get("dependencies") or {})
        if name.lower() != "python"
    }
    dev = _names_from(poetry.get("dev-dependencies") or {})
    for group in (poetry.get("group") or {}).values():
        if isinstance(group, dict):
            dev |= {
                canonicalize_name(name)
                for name in (group.get("dependencies") or {})
                if name.lower() != "python"
            }
    return direct, dev - direct


class PoetryLockResolver(LockfileResolver):
    """Read poetry.lock: the graph Poetry resolved, pinned."""

    id = "poetry-lock"
    label = "poetry.lock"
    lockfiles = ("poetry.lock",)
    supersedes = ("pyproject.toml",)

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        lock = self.lockfile(ctx)
        try:
            data = _load_toml(lock)
        except Exception as exc:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"could not read poetry.lock: {exc}")
        packages = data.get("package")
        if not isinstance(packages, list) or not packages:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          "poetry.lock listed no packages")

        direct, dev = poetry_declarations(ctx.path("pyproject.toml"))
        collected = []
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = str(package.get("name") or "")
            version = str(package.get("version") or "")
            if not name or not version:
                continue
            canonical = canonicalize_name(name)
            # Poetry <1.5 recorded the group on the package itself.
            category = str(package.get("category") or "").lower()
            collected.append(_python_dependency(
                name, version, str(lock), self.id,
                direct=canonical in direct or canonical in dev,
                is_dev=canonical in dev or category == "dev",
            ))
        if not collected:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          "poetry.lock contained no resolved packages")
        return resolved(self, collected)


class PipenvLockResolver(LockfileResolver):
    """Read Pipfile.lock, marker evaluation and all."""

    id = "pipenv-lock"
    label = "Pipfile.lock"
    lockfiles = ("Pipfile.lock",)
    supersedes = ("Pipfile", "Pipfile.lock")

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        lock = self.lockfile(ctx)
        report = parse_pipfile_lock(lock, **ctx.options.python_parser_kwargs())
        if report.errors:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          report.errors[0].message)
        direct = set()
        pipfile = ctx.path("Pipfile")
        if pipfile is not None:
            try:
                data = _load_toml(pipfile)
                direct = _names_from(data.get("packages") or {}) | _names_from(
                    data.get("dev-packages") or {})
            except Exception:
                direct = set()
        for dependency in report.dependencies:
            dependency.resolver = self.id
            dependency.direct = not direct or dependency.name in direct
        outcome = resolved(self, report.dependencies)
        outcome.diagnostics = [f"{len(report.inactive)} skipped by marker"]
        return outcome


class PythonLockAdvice:
    """
    Which Python manager a project uses, and whether its lock is present.

    Used to explain, when nothing could be resolved, exactly which tool would
    close the gap -- and to offer installation help when that tool is missing
    too.
    """

    MANAGERS = [
        ("uv", "uv.lock", "uv lock"),
        ("poetry", "poetry.lock", "poetry lock"),
        ("pipenv", "Pipfile.lock", "pipenv lock"),
    ]

    @staticmethod
    def declared(ctx: "ResolutionContext") -> list:
        declared = []
        pyproject = ctx.path("pyproject.toml")
        tables = {}
        if pyproject is not None:
            try:
                tables = _load_toml(pyproject)
            except Exception:
                tables = {}
        tool_tables = tables.get("tool") or {}
        backend = str(((tables.get("build-system") or {}).get("build-backend")
                       or "")).lower()

        if "uv" in tool_tables or ctx.has("uv.lock"):
            declared.append("uv")
        if "poetry" in tool_tables or "poetry" in backend or ctx.has("poetry.lock"):
            declared.append("poetry")
        if ctx.has("Pipfile", "Pipfile.lock"):
            declared.append("pipenv")
        return declared


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


class CargoLockResolver(LockfileResolver):
    """Read Cargo.lock: the exact crate graph Cargo resolved."""

    id = "cargo-lock"
    label = "Cargo.lock"
    lockfiles = ("Cargo.lock",)
    supersedes = ("Cargo.toml",)

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        lock = self.lockfile(ctx)
        try:
            data = _load_toml(lock)
        except Exception as exc:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"could not read Cargo.lock: {exc}")
        packages = data.get("package")
        if not isinstance(packages, list) or not packages:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          "Cargo.lock listed no packages")

        manifest = ctx.path("Cargo.toml")
        root_name, direct, dev = "", set(), set()
        if manifest is not None:
            try:
                toml = _load_toml(manifest)
                root_name = str((toml.get("package") or {}).get("name") or "")
                direct = set(toml.get("dependencies") or {}) | set(
                    toml.get("build-dependencies") or {})
                dev = set(toml.get("dev-dependencies") or {})
            except Exception:
                pass

        collected = []
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = str(package.get("name") or "")
            version = str(package.get("version") or "")
            if not name or not version or name == root_name:
                continue
            collected.append(Dependency(
                name=name,
                version=version,
                ecosystem="crates.io",
                source_file=str(lock),
                is_dev=name in dev and name not in direct,
                resolution="lockfile",
                resolver=self.id,
                direct=name in direct or name in dev,
            ))
        if not collected:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          "Cargo.lock contained no resolved crates")
        return resolved(self, collected)


class CargoMetadataResolver(Resolver):
    """Ask Cargo for the resolved crate graph when there is no Cargo.lock."""

    id = "cargo"
    label = "cargo metadata"
    tool_id = "cargo"
    executables = ("cargo",)
    supersedes = ("Cargo.toml",)
    required_for = "the resolved Rust crate graph"

    def triggers(self, ctx: ResolutionContext) -> bool:
        return ctx.has("Cargo.toml")

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        argv = [*command.argv, "metadata", "--format-version", "1"]
        if ctx.options.offline:
            argv.append("--offline")
        process, error, reason = run_tool(argv, ctx.project_dir, ctx.timeout)
        if error is not None:
            return failed(self, error, reason, command)
        output = (process.stdout or "") + (process.stderr or "")
        if process.returncode != 0:
            return failed(self, ToolErrorKind.RESOLUTION_FAILED,
                          _first_error_line(output, "cargo exited with an error"),
                          command, output)
        try:
            data = json.loads(process.stdout or "")
        except ValueError as exc:
            return failed(self, ToolErrorKind.OUTPUT_INVALID,
                          f"cargo did not return JSON ({exc})", command, output)

        workspace = set(data.get("workspace_members") or [])
        resolve_graph = data.get("resolve") or {}
        root = resolve_graph.get("root")
        direct = set()
        for node in resolve_graph.get("nodes") or []:
            if isinstance(node, dict) and node.get("id") == root:
                for dep in node.get("deps") or []:
                    if isinstance(dep, dict) and isinstance(dep.get("name"), str):
                        direct.add(dep["name"].replace("_", "-"))

        source = str(ctx.path("Cargo.toml"))
        collected = []
        for package in data.get("packages") or []:
            if not isinstance(package, dict):
                continue
            name = str(package.get("name") or "")
            version = str(package.get("version") or "")
            if not name or not version or package.get("id") in workspace:
                continue
            collected.append(Dependency(
                name=name, version=version, ecosystem="crates.io",
                source_file=source, resolution="native", resolver=self.id,
                direct=name.replace("_", "-") in direct,
            ))
        if not collected:
            return failed(self, ToolErrorKind.RESOLUTION_FAILED,
                          "cargo reported no packages", command, output)
        return resolved(self, collected, command, output,
                        [f"resolution command: {' '.join(argv)}"])


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


class GoListResolver(Resolver):
    """
    Ask the Go toolchain which module versions it selects.

    go.mod records requirements; minimal version selection and any ``replace``
    directive decide what is actually built, and only Go knows the outcome.
    """

    id = "go"
    label = "go list"
    tool_id = "go"
    executables = ("go",)
    supersedes = ("go.mod",)
    required_for = "the module versions Go selects"

    def triggers(self, ctx: ResolutionContext) -> bool:
        return ctx.has("go.mod")

    def resolve(self, ctx: ResolutionContext,
                command: ToolCommand | None) -> Resolution:
        argv = [*command.argv, "list", "-m", "-json", "all"]
        # Go has no offline flag: refusing the proxy is what confines it to
        # the module cache already on disk.
        environment = {"GOPROXY": "off"} if ctx.options.offline else None
        process, error, reason = run_tool(argv, ctx.project_dir, ctx.timeout,
                                          environment)
        if error is not None:
            return failed(self, error, reason, command)
        output = (process.stdout or "") + (process.stderr or "")
        if process.returncode != 0:
            return failed(self, ToolErrorKind.RESOLUTION_FAILED,
                          _first_error_line(output, "go exited with an error"),
                          command, output)
        try:
            modules = json_objects(process.stdout or "")
        except ValueError as exc:
            return failed(self, ToolErrorKind.OUTPUT_INVALID, str(exc),
                          command, output)

        source = str(ctx.path("go.mod"))
        collected = []
        for module in modules:
            if not isinstance(module, dict) or module.get("Main"):
                continue
            direct = not module.get("Indirect")
            replacement = module.get("Replace")
            if isinstance(replacement, dict):
                module = replacement
            path = str(module.get("Path") or "")
            version = str(module.get("Version") or "")
            if not path or not version:
                continue          # a filesystem replacement has no version
            collected.append(Dependency(
                name=path,
                version=version.removeprefix("v"),
                ecosystem="Go",
                source_file=source,
                resolution="native",
                resolver=self.id,
                direct=direct,
            ))
        if not collected:
            return failed(self, ToolErrorKind.RESOLUTION_FAILED,
                          "go listed no modules", command, output)
        return resolved(self, collected, command, output,
                        [f"resolution command: {' '.join(argv)}"])


# ---------------------------------------------------------------------------
# Ecosystem registry and discovery
# ---------------------------------------------------------------------------


@dataclass
class ScanOptions:
    """Everything the parsers and resolvers need to know about the scan."""

    environment: dict = field(default_factory=dict)   # PEP 508 marker overrides
    resolver: VersionResolver | None = None
    skip_dev: bool = False
    verbose: bool = False
    no_native: bool = False          # never run project tooling; parse only
    offline: bool = False            # ask resolvers not to reach the network
    require_native: bool = False     # a missing resolver tool fails the scan
    resolver_timeout: int = DEFAULT_RESOLVER_TIMEOUT
    rerun_hint: str = "checkdeps ."  # shown in installation help

    def python_parser_kwargs(self) -> dict:
        return {
            "environment": self.environment,
            "resolver": self.resolver or VersionResolver(),
        }


@dataclass
class ScanRecord:
    """What happened to one manifest, ready for any presentation layer."""

    ecosystem: str
    target: str
    resolver: str
    native: bool = False
    total: int = 0
    direct: int = 0
    transitive: int = 0
    indeterminate: int = 0
    warnings: list = field(default_factory=list)
    missing_tool: MissingTool | None = None
    diagnostics: list = field(default_factory=list)


@dataclass
class ResolverProfile:
    """
    Everything checkdeps knows about one ecosystem.

    Adding an ecosystem means adding a profile -- discovery, resolution,
    fallback and the OSV mapping all read from here, and the scanning layer
    below never learns a new name.
    """

    ecosystem: str                  # label shown to the user
    osv_ecosystem: str              # the name OSV knows it by
    manifests: tuple                # declaration files, in preference order
    lockfiles: tuple                # resolved-state files
    resolvers: tuple                # ordered candidates, most authoritative first
    static_parsers: dict            # filename -> parser, the always-available path
    advisor: object = None          # optional hook adding guidance to a record

    @property
    def detection(self) -> tuple:
        return tuple(self.manifests) + tuple(self.lockfiles)

    @property
    def static_parser(self):
        """The parser for this profile's primary manifest."""
        return self.static_parsers.get(self.manifests[0]) if self.manifests else None

    def files_in(self, project_dir: Path) -> dict:
        found = {}
        for name in self.detection:
            candidate = project_dir / name
            if candidate.exists():
                found[name] = candidate
        return found

    def primary_target(self, ctx: "ResolutionContext") -> Path:
        for name in self.detection:
            if name in ctx.files:
                return ctx.files[name]
        return ctx.project_dir

    def fallback_description(self, ctx: "ResolutionContext") -> str:
        names = [name for name in self.manifests if name in ctx.files]
        if not names:
            return "no static analysis is possible for this project"
        return "static {} analysis".format(" and ".join(names))

    def candidates(self, ctx: "ResolutionContext") -> list:
        applicable = [r for r in self.resolvers if r.triggers(ctx)]
        # A project that names its package manager gets that one first.
        return sorted(applicable, key=lambda resolver: resolver.priority(ctx))

    def resolve(self, ctx: "ResolutionContext", record: ScanRecord):
        """Try each candidate resolver in turn; None when none could run."""
        fallback = self.fallback_description(ctx)
        for resolver in self.candidates(ctx):
            command = None
            if resolver.needs_tool:
                command = resolver.find_command(ctx)
                if command is None:
                    tool = TOOLS[resolver.tool_id]
                    record.warnings.append(f"{tool.command} not found")
                    if record.missing_tool is None:
                        record.missing_tool = resolver.missing(ctx, fallback)
                    continue
                if resolver.minimum_version or ctx.options.verbose:
                    command.version = tool_version(command, resolver.version_argument)
                if resolver.minimum_version:
                    if version_at_least(command.version,
                                        resolver.minimum_version) is False:
                        tool = TOOLS[resolver.tool_id]
                        record.warnings.append(
                            f"{tool.display_name} {command.version} is older than "
                            f"the {resolver.minimum_version} this resolver needs"
                        )
                        if record.missing_tool is None:
                            record.missing_tool = resolver.missing(
                                ctx, fallback, ToolErrorKind.TOOL_VERSION_TOO_OLD,
                                command.version,
                            )
                        continue
                record.diagnostics.append(
                    f"{resolver.describe(command)}: {command.display}"
                    + (f" ({command.version})" if command.version else "")
                )

            outcome = resolver.resolve(ctx, command)
            record.diagnostics.extend(outcome.diagnostics)
            if outcome.ok:
                return outcome
            record.warnings.append(
                f"{resolver.describe(command)} could not resolve "
                f"({outcome.error}): {outcome.reason}"
            )
            if outcome.output and ctx.options.verbose:
                record.diagnostics.extend(_log_tail(outcome.output))
        return None

    def scan(self, ctx: "ResolutionContext") -> tuple:
        """Resolve or parse one project, returning (report, records)."""
        report = ParseReport()
        records: list = []
        outcome = None
        pending = ScanRecord(self.ecosystem, str(self.primary_target(ctx)), "")

        if self.resolvers and not ctx.options.no_native:
            outcome = self.resolve(ctx, pending)

        superseded: set = set()
        if outcome is not None:
            winner = next((resolver for resolver in self.resolvers
                           if resolver.id == outcome.resolver_id), None)
            superseded = set(winner.supersedes) if winner is not None else set()
            report.dependencies.extend(outcome.dependencies)
            pending.resolver = outcome.resolver_label
            pending.native = True
            _fill_counts(pending, outcome.dependencies)
            records.append(pending)
            pending = None

        for name in self.manifests:
            path = ctx.files.get(name)
            if path is None or name in superseded:
                continue
            parser = self.static_parsers.get(name)
            if parser is None:
                continue
            sub = _run_parser(parser, path, ctx.options)
            record = pending or ScanRecord(self.ecosystem, str(path), "")
            record.target = str(path)
            record.resolver = f"static {name} analysis"
            record.native = False
            _fill_counts(record, sub.dependencies)
            report.merge(sub)
            records.append(record)
            pending = None

        # The registry owns the OSV mapping, so nothing downstream has to
        # learn a new ecosystem name -- and no resolver can drift from it.
        for dependency in report.dependencies:
            dependency.ecosystem = self.osv_ecosystem
        for dependency in report.inactive:
            dependency.ecosystem = self.osv_ecosystem

        if self.advisor is not None:
            self.advisor(ctx, records[0] if records else pending)

        if pending is not None:          # nothing to parse, but something to say
            pending.resolver = "no analysis available"
            records.append(pending)

        if ctx.options.require_native and self.candidates(ctx) and outcome is None:
            target = str(self.primary_target(ctx))
            report.issues.append(ParseIssue(
                "native_resolution_required", "error",
                f"{self.ecosystem}: native resolution was required but no "
                "resolver could run", target,
            ))
        return report, records


def _fill_counts(record: ScanRecord, dependencies: list) -> None:
    record.total = len(dependencies)
    record.direct = sum(1 for dep in dependencies if dep.direct)
    record.transitive = record.total - record.direct
    record.indeterminate = sum(1 for dep in dependencies if not dep.resolved)


def _log_tail(output: str, limit: int = 40) -> list:
    """The tail of a tool's log -- only ever shown with --verbose."""
    lines = [redact_secrets(line.rstrip())
             for line in output.splitlines() if line.strip()]
    trimmed = lines[-limit:]
    notes = []
    if len(lines) > len(trimmed):
        notes.append(f"... {len(lines) - len(trimmed)} earlier lines")
    notes.extend(trimmed)
    return notes


def python_lock_advisor(ctx: "ResolutionContext", record: ScanRecord) -> None:
    """
    Explain the one thing that would let checkdeps resolve this project.

    Ranges in a pyproject.toml name no version.  The project's own manager can
    write down which versions it picks -- so say which manager, whether it is
    installed, and what to run.  checkdeps never runs it: locking a project is
    the developer's decision, not a scanner's.
    """
    if record is None or record.native:
        return
    for manager in PythonLockAdvice.declared(ctx):
        lockfile, command = {
            "uv": ("uv.lock", "uv lock"),
            "poetry": ("poetry.lock", "poetry lock"),
            "pipenv": ("Pipfile.lock", "pipenv lock"),
        }[manager]
        if ctx.has(lockfile):
            continue                      # present but unreadable: already warned
        tool = TOOLS[manager]
        if shutil.which(tool.command) is None:
            record.warnings.append(
                f"{tool.display_name} is not installed and there is no {lockfile}"
            )
            if record.missing_tool is None:
                record.missing_tool = MissingTool(
                    tool_id=manager,
                    command=tool.command,
                    resolver=f"{manager}-lock",
                    project=str(ctx.profile.primary_target(ctx)),
                    required_for="exact versions for this Python project",
                    fallback=ctx.profile.fallback_description(ctx),
                    next_step=command,
                )
        else:
            record.warnings.append(
                f"no {lockfile} -- run '{command}' so checkdeps can read exact "
                "versions"
            )
        return


PROFILES = [
    ResolverProfile(
        ecosystem="Maven",
        osv_ecosystem="Maven",
        manifests=("pom.xml",),
        lockfiles=(),
        resolvers=(MavenResolver(),),
        static_parsers={"pom.xml": parse_pom_xml},
    ),
    ResolverProfile(
        ecosystem="Gradle",
        osv_ecosystem="Maven",
        manifests=("build.gradle", "build.gradle.kts"),
        lockfiles=(),
        resolvers=(GradleResolver(),),
        static_parsers={
            "build.gradle": parse_build_gradle,
            "build.gradle.kts": parse_build_gradle,
        },
    ),
    ResolverProfile(
        ecosystem="npm",
        osv_ecosystem="npm",
        manifests=("package.json",),
        lockfiles=("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
                   "yarn.lock"),
        resolvers=(PnpmResolver(), NpmLockResolver(), YarnLockResolver(),
                   NpmTreeResolver()),
        static_parsers={"package.json": parse_package_json},
    ),
    ResolverProfile(
        ecosystem="Python",
        osv_ecosystem="PyPI",
        manifests=("requirements.txt", "pyproject.toml", "Pipfile"),
        lockfiles=("uv.lock", "poetry.lock", "Pipfile.lock"),
        resolvers=(UvLockResolver(), PoetryLockResolver(), PipenvLockResolver()),
        static_parsers={
            "requirements.txt": parse_requirements_txt,
            "pyproject.toml": parse_pyproject_toml,
            "Pipfile": parse_pipfile,
        },
        advisor=python_lock_advisor,
    ),
    ResolverProfile(
        ecosystem="Rust",
        osv_ecosystem="crates.io",
        manifests=("Cargo.toml",),
        lockfiles=("Cargo.lock",),
        resolvers=(CargoLockResolver(), CargoMetadataResolver()),
        static_parsers={"Cargo.toml": parse_cargo_toml},
    ),
    ResolverProfile(
        ecosystem="Go",
        osv_ecosystem="Go",
        manifests=("go.mod",),
        lockfiles=(),
        resolvers=(GoListResolver(),),
        static_parsers={"go.mod": parse_go_mod},
    ),
]

PROFILES_BY_ECOSYSTEM = {profile.ecosystem: profile for profile in PROFILES}

# Derived from the registry so a new ecosystem needs no second list.
FILE_PARSERS = {
    name: parser
    for profile in PROFILES
    for name, parser in profile.static_parsers.items()
}
DETECTION_ORDER = [name for profile in PROFILES for name in profile.detection]

PROFILE_FOR_FILE = {
    name: profile for profile in PROFILES for name in profile.detection
}

# Parsers that accept the scan target environment and the version resolver.
_ENVIRONMENT_AWARE = {
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_pipfile,
    parse_pipfile_lock,
}

# Patterns tried when a named file is not one of the exact manifest names.
FILE_PATTERNS = [
    (lambda n: n.endswith("pom.xml"),          parse_pom_xml),
    (lambda n: n.endswith("package.json"),     parse_package_json),
    (lambda n: n.endswith("requirements.txt"), parse_requirements_txt),
    (lambda n: n.endswith(".gradle") or n.endswith(".gradle.kts"),
     parse_build_gradle),
    (lambda n: n == "Pipfile.lock",            parse_pipfile_lock),
    (lambda n: n == "Pipfile",                 parse_pipfile),
    (lambda n: n.endswith("pyproject.toml"),   parse_pyproject_toml),
    (lambda n: n.endswith("Cargo.toml"),       parse_cargo_toml),
    (lambda n: n == "go.mod",                  parse_go_mod),
]


def _parser_for_file(path: Path):
    """Return the appropriate static parser for a file, or None."""
    name = path.name
    if name in FILE_PARSERS:
        return FILE_PARSERS[name]
    for matcher, parser in FILE_PATTERNS:
        if matcher(name):
            return parser
    return None


def _run_parser(parser, path: Path, options: ScanOptions) -> ParseReport:
    kwargs = options.python_parser_kwargs() if parser in _ENVIRONMENT_AWARE else {}
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
    case across the modules of one build -- it becomes a single OSV query, and
    the other manifests are recorded on the surviving record.
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


def resolution_context(profile: ResolverProfile, project_dir: Path,
                       options: ScanOptions | None = None) -> ResolutionContext:
    """Build the context a resolver sees for one project directory."""
    options = options if options is not None else ScanOptions()
    return ResolutionContext(profile, project_dir,
                             profile.files_in(project_dir), options)


def scan_project(project_dir: Path, options: ScanOptions,
                 profiles=None) -> tuple:
    """Run every applicable ecosystem profile over one directory."""
    report = ParseReport()
    for profile in profiles or PROFILES:
        files = profile.files_in(project_dir)
        if not files:
            continue
        ctx = ResolutionContext(profile, project_dir, files, options)
        sub, records = profile.scan(ctx)
        report.merge(sub)
        report.records.extend(records)
    return report


def scan_named_file(path: Path, options: ScanOptions) -> ParseReport:
    """
    Scan one file the user named explicitly.

    A named manifest still gets its ecosystem's native resolution: pointing at
    backend/pom.xml should mean the same thing as pointing at backend/.
    """
    profile = PROFILE_FOR_FILE.get(path.name)
    if profile is not None:
        return scan_project(path.parent if str(path.parent) else Path("."),
                            options, profiles=[profile])

    parser = _parser_for_file(path)
    if parser is None:
        return None
    sub = _run_parser(parser, path, options)
    record = ScanRecord("Other", str(path), f"static {path.name} analysis")
    _fill_counts(record, sub.dependencies)
    sub.records.append(record)
    return sub


def discover_and_parse(paths: list, skip_dev: bool = False,
                       options: ScanOptions | None = None,
                       quiet: bool = False) -> ParseReport:
    options = options or ScanOptions(skip_dev=skip_dev)
    options.skip_dev = skip_dev or options.skip_dev
    report = ParseReport()

    def emit(sub: ParseReport) -> None:
        report.merge(sub)
        if not quiet:
            for record in sub.records:
                print_scan_record(record, options)

    for p in paths:
        if p.is_dir():
            sub = scan_project(p, options)
            if not sub.records:
                if not quiet:
                    console.print(
                        f"[yellow]Warning:[/yellow] No supported manifest found in {p}"
                    )
                continue
            emit(sub)
        elif p.is_file():
            sub = scan_named_file(p, options)
            if sub is None:
                if not quiet:
                    console.print(f"[yellow]Warning:[/yellow] Unsupported file: {p}")
                continue
            emit(sub)
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
            console.print(f"\n  [dim]Skipped {skipped} dev dependencies[/dim]")

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
    if any(dep.resolver is None for dep in unresolved):
        console.print(
            "[dim]These came from static manifest analysis. Letting the "
            "project's own tooling resolve it -- the default, when that "
            "tooling is installed -- supplies the versions it selects.[/dim]"
        )


def missing_tool_lines(missing: MissingTool, rerun: str = "checkdeps .",
                       platform: str | None = None,
                       os_release_path: str = OS_RELEASE_PATH) -> list:
    """
    The help text for a tool checkdeps could not use.

    Plain lines, no console: resolvers produce the fact, this produces the
    words, and tests can read them without a terminal.  Everything the user
    needs is here -- what is missing, why it mattered, what platform they are
    on, the one command that installs it, and what checkdeps did instead.
    """
    tool = missing.tool
    advice = install_advice(tool.id, platform, os_release_path)
    lines = []

    if missing.kind == ToolErrorKind.TOOL_VERSION_TOO_OLD:
        found = missing.found_version or "the installed version"
        lines.append(
            f"{tool.display_name} {found} is older than the "
            f"{missing.required_version} this resolver needs."
        )
    else:
        lines.append(f"{tool.display_name} is not installed.")
    lines.append("")
    lines.append(f"checkdeps uses {tool.display_name} ({tool.command}) to "
                 f"{tool.purpose}.")
    lines.append("")

    platform_name = describe_platform(advice.platform, os_release_path)
    if advice.package_manager is not None:
        lines.append(f"{platform_name} detected, "
                     f"{advice.package_manager.display_name} detected.")
    else:
        lines.append(f"{platform_name} detected, but no supported package "
                     "manager was found.")
    lines.append("")

    verb = "Upgrade" if missing.kind == ToolErrorKind.TOOL_VERSION_TOO_OLD \
        else "Install"
    if advice.command:
        lines.append(f"{verb} {tool.display_name}:")
        lines.append(f"  {advice.command}")
    else:
        # Nothing confident to offer: the official instructions beat a guess.
        lines.append(f"{verb} {tool.display_name} with your preferred package "
                     "manager, or follow:")
        lines.append(f"  {advice.homepage}")
    lines.append("")

    if missing.next_step:
        lines.append("Then run, in the project:")
        lines.append(f"  {missing.next_step}")
        lines.append("")

    lines.append("Then rerun:")
    lines.append(f"  {rerun}")
    lines.append("")
    lines.append(f"Continuing with {missing.fallback}.")
    lines.append("Some dependency versions may remain indeterminate.")
    return lines


def missing_tool_json(missing: MissingTool, platform: str | None = None,
                      os_release_path: str = OS_RELEASE_PATH) -> dict:
    """The same fact, structured, for --format json and other consumers."""
    advice = install_advice(missing.tool_id, platform, os_release_path)
    return {
        "type": "missing_tool",
        "tool": missing.tool_id,
        "displayName": missing.tool.display_name,
        "command": missing.command,
        "kind": missing.kind,
        "resolver": missing.resolver,
        "project": missing.project,
        "requiredFor": missing.required_for,
        "foundVersion": missing.found_version,
        "requiredVersion": missing.required_version,
        "platform": advice.platform,
        "packageManager": (advice.package_manager.id
                           if advice.package_manager else None),
        "installer": advice.source,
        "installCommand": advice.command,
        "nextStep": missing.next_step,
        "homepage": advice.homepage,
        "fallback": missing.fallback,
        "fallbackUsed": True,
    }


def print_missing_tool(missing: MissingTool, options: "ScanOptions") -> None:
    console.print()
    for line in missing_tool_lines(missing, options.rerun_hint):
        console.print(f"    [yellow]{line}[/yellow]" if line and
                      line.endswith(("installed.", "needs.")) else f"    {line}",
                      highlight=False)


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or singular + "s")


def print_scan_record(record: ScanRecord, options: "ScanOptions") -> None:
    """One block per manifest: what it is, how it was read, what came out."""
    console.print()
    console.print(f"  [bold]{record.ecosystem}[/bold]: {record.target}")
    for warning in record.warnings:
        console.print(f"    [yellow]warning[/yellow] {warning}")
    console.print(f"    [dim]resolver:[/dim] {record.resolver}")

    noun = _plural(record.total, "dependency", "dependencies")
    if record.native:
        console.print(
            f"    [cyan]{record.total}[/cyan] resolved {noun} "
            f"[dim]({record.direct} direct, {record.transitive} transitive)[/dim]"
        )
    else:
        line = f"    [cyan]{record.total}[/cyan] declared {noun}"
        if record.indeterminate:
            line += (f", [yellow]{record.indeterminate}[/yellow] "
                     f"{_plural(record.indeterminate, 'version')} indeterminate")
        console.print(line)

    if record.missing_tool is not None:
        print_missing_tool(record.missing_tool, options)
    if options.verbose:
        for line in record.diagnostics:
            console.print(f"    [dim]{redact_secrets(line)}[/dim]", highlight=False)


def print_resolved_dependencies(report: ParseReport) -> None:
    """List what native resolution produced, declared packages first."""
    resolved_deps = [d for d in report.dependencies if d.resolver]
    if not resolved_deps:
        return
    for label, group in (
        ("DIRECT", [d for d in resolved_deps if d.direct]),
        ("TRANSITIVE", [d for d in resolved_deps if not d.direct]),
    ):
        if not group:
            continue
        console.print()
        console.print(f"[bold]{label}[/bold]")
        for dep in sorted(group, key=lambda d: (d.ecosystem, d.name, d.version or "")):
            scope = f" [dim]({dep.scope})[/dim]" if dep.scope else ""
            console.print(f"  {dep.name}:{dep.version}{scope}", highlight=False)
            if dep.introduced_by:
                console.print(f"    [dim]via {dep.introduced_by}[/dim]",
                              highlight=False)
            for extra in dep.also_used_by:
                console.print(f"    [dim]also used by {extra}[/dim]",
                              highlight=False)


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
    native = [d for d in deps if d.resolver]
    if native:
        direct = sum(1 for d in native if d.direct)
        parts.append(
            f"[cyan]{direct}[/cyan] direct + [cyan]{len(native) - direct}[/cyan] "
            "transitive natively resolved"
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
        "resolver": dep.resolver,
        "introduced_by": dep.introduced_by,
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

    missing_tools = [
        missing_tool_json(record.missing_tool)
        for record in report.records if record.missing_tool is not None
    ]
    output = {
        "scanned": len(deps),
        "resolution": [
            {
                "ecosystem": record.ecosystem,
                "source": record.target,
                "resolver": record.resolver,
                "native": record.native,
                "dependencies": record.total,
                "direct": record.direct,
                "transitive": record.transitive,
                "indeterminate": record.indeterminate,
                "warnings": record.warnings,
            }
            for record in report.records
        ],
        "missing_tools": missing_tools,
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
  checkdeps --verbose                show the resolved dependency graph
  checkdeps --no-native              never run build tooling; parse statically

Each ecosystem is resolved by its own tooling where that is possible: Maven or
Gradle (wrapper first) for Java, the npm/Yarn lockfile or pnpm for JavaScript,
uv/poetry/Pipfile locks for Python, Cargo.lock or cargo for Rust and go list
for Go.  Only read-only dependency-inspection commands are ever run -- never a
build, test, install or package step -- and --no-native turns execution off.
When a tool is missing, checkdeps explains how to install it on this platform
and continues with static manifest analysis.
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
        help="List the resolved dependency graph, the resolver and tool used, "
             "and the tool's own output when resolution fails",
    )
    parser.add_argument(
        "--no-native",
        "--no-maven",
        dest="no_native",
        action="store_true",
        help="Never execute project build tooling; analyse manifests statically",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Ask native resolvers not to reach the network",
    )
    parser.add_argument(
        "--require-native-resolution",
        dest="require_native",
        action="store_true",
        help="Exit with code 1 when an ecosystem's native resolver could not "
             "run (default: fall back to static analysis)",
    )
    parser.add_argument(
        "--resolver-timeout",
        "--maven-timeout",
        dest="resolver_timeout",
        type=int,
        default=DEFAULT_RESOLVER_TIMEOUT,
        metavar="SECONDS",
        help=f"Time budget for one native resolution "
             f"(default: {DEFAULT_RESOLVER_TIMEOUT})",
    )

    args = parser.parse_args()
    scan_paths = [Path(p) for p in (args.paths or ["."])]

    quiet = args.format == "json"
    if not quiet:
        console.print("[bold]checkdeps[/bold] -- CVE scanner via OSV (https://osv.dev)\n")
        if args.verbose:
            manager = detect_package_manager()
            console.print(
                f"[dim]platform: {describe_platform()}"
                + (f", {manager.display_name} detected" if manager
                   else ", no supported package manager detected")
                + "[/dim]"
            )
        console.print("[dim]Parsing dependency files...[/dim]")

    options = ScanOptions(
        environment=build_environment(args),
        resolver=(VersionResolver.from_installed() if args.resolve_from_env
                  else VersionResolver()),
        skip_dev=args.skip_dev,
        verbose=args.verbose,
        no_native=args.no_native,
        offline=args.offline,
        require_native=args.require_native,
        resolver_timeout=args.resolver_timeout,
        rerun_hint="checkdeps " + " ".join(str(p) for p in scan_paths),
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
        print_resolved_dependencies(report)

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

    if args.require_native and any(
            issue.kind == "native_resolution_required" for issue in report.issues):
        sys.exit(1)
    if args.fail_on_vuln and count > 0:
        sys.exit(1)
    if args.fail_on_unresolved and (report.unresolved or report.errors):
        sys.exit(1)


if __name__ == "__main__":
    main()
