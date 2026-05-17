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

Data source: OSV (https://osv.dev) -- free, no API key required.
"""

import argparse
import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import requests
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


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    source_file: str
    is_dev: bool = False


@dataclass
class Vulnerability:
    vuln_id: str
    summary: str
    severity: str
    cvss_score: object  # float or None
    aliases: list = field(default_factory=list)
    published: str = ""


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _strip_semver_range(version: str) -> str:
    """Remove npm-style range operators to get a concrete version."""
    version = version.strip()
    version = re.sub(r"^[\^~>=<*xX]+", "", version)
    version = version.split()[0] if version.split() else "0.0.0"
    return version or "0.0.0"


def parse_package_json(path: Path) -> list:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not parse {path}: {e}")
        return []

    deps = []
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
            deps.append(Dependency(name, version, "npm", str(path), is_dev=is_dev))
    return deps


def parse_pom_xml(path: Path) -> list:
    try:
        tree = ET.parse(path)
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not parse {path}: {e}")
        return []

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
            text = text.replace(f"${{{key}}}", val)
        return text

    deps = []
    for dep in root.iter(f"{ns}dependency"):
        group = dep.find(f"{ns}groupId")
        artifact = dep.find(f"{ns}artifactId")
        version_el = dep.find(f"{ns}version")
        scope_el = dep.find(f"{ns}scope")

        if group is None or artifact is None or version_el is None:
            continue

        version = resolve(version_el.text.strip() if version_el.text else "")
        if not version or version.startswith("${"):
            continue  # unresolvable placeholder; skip

        scope = (
            scope_el.text.strip().lower()
            if scope_el is not None and scope_el.text
            else "compile"
        )
        is_dev = scope in ("test", "provided")
        name = f"{group.text.strip()}:{artifact.text.strip()}"
        deps.append(Dependency(name, version, "Maven", str(path), is_dev=is_dev))
    return deps


def parse_requirements_txt(path: Path) -> list:
    deps = []
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not parse {path}: {e}")
        return []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", "-", "http://", "https://")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[><=!~^]+\s*([^\s,;#\[]+))?", line)
        if not m:
            continue
        name = m.group(1)
        version = m.group(2) or "0.0.0"
        version = re.sub(r"^[><=!~^]+", "", version).split(",")[0].strip()
        deps.append(Dependency(name, version, "PyPI", str(path)))
    return deps


def parse_pipfile_lock(path: Path) -> list:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not parse {path}: {e}")
        return []

    deps = []
    for section, is_dev in [("default", False), ("develop", True)]:
        for name, info in data.get(section, {}).items():
            version = info.get("version", "==0.0.0").lstrip("=")
            deps.append(Dependency(name, version, "PyPI", str(path), is_dev=is_dev))
    return deps


def parse_pipfile(path: Path) -> list:
    lock_path = path.parent / "Pipfile.lock"
    if lock_path.exists():
        return parse_pipfile_lock(lock_path)
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not parse {path}: {e}")
        return []

    deps = []
    for section, is_dev in [("packages", False), ("dev-packages", True)]:
        for name, spec in data.get(section, {}).items():
            version = spec if isinstance(spec, str) else "*"
            version = re.sub(r"^[><=!~^*]+", "", version).strip() or "0.0.0"
            deps.append(Dependency(name, version, "PyPI", str(path), is_dev=is_dev))
    return deps


def parse_pyproject_toml(path: Path) -> list:
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not parse {path}: {e}")
        return []

    deps = []

    # PEP 621 / setuptools style
    for spec in data.get("project", {}).get("dependencies", []):
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[><=!~^]+\s*([^\s,;#\[]+))?", spec)
        if m:
            name = m.group(1)
            version = re.sub(r"^[><=!~^]+", "", m.group(2) or "0.0.0")
            deps.append(Dependency(name, version, "PyPI", str(path)))

    # Poetry style
    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        version = (
            spec
            if isinstance(spec, str)
            else spec.get("version", "*")
            if isinstance(spec, dict)
            else "*"
        )
        version = re.sub(r"^[\^~>=<*]+", "", str(version)).strip() or "0.0.0"
        deps.append(Dependency(name, version, "PyPI", str(path)))
    for name, spec in poetry.get("dev-dependencies", {}).items():
        version = (
            spec
            if isinstance(spec, str)
            else spec.get("version", "*")
            if isinstance(spec, dict)
            else "*"
        )
        version = re.sub(r"^[\^~>=<*]+", "", str(version)).strip() or "0.0.0"
        deps.append(Dependency(name, version, "PyPI", str(path), is_dev=True))

    return deps


def parse_cargo_toml(path: Path) -> list:
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not parse {path}: {e}")
        return []

    deps = []
    for section, is_dev in [
        ("dependencies", False),
        ("dev-dependencies", True),
        ("build-dependencies", False),
    ]:
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                version = re.sub(r"^[\^~>=<*]+", "", spec).strip() or "0.0.0"
            elif isinstance(spec, dict):
                version = (
                    re.sub(r"^[\^~>=<*]+", "", spec.get("version", "0.0.0")).strip()
                    or "0.0.0"
                )
            else:
                continue
            deps.append(Dependency(name, version, "crates.io", str(path), is_dev=is_dev))
    return deps


def parse_go_mod(path: Path) -> list:
    deps = []
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not parse {path}: {e}")
        return []

    in_require = False
    for line in lines:
        line = line.strip()
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
                name = parts[0]
                version = parts[1].lstrip("v")
                deps.append(Dependency(name, version, "Go", str(path)))
    return deps


# ---------------------------------------------------------------------------
# File discovery and dispatch
# ---------------------------------------------------------------------------

FILE_PARSERS = {
    "pom.xml": parse_pom_xml,
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "Pipfile.lock": parse_pipfile_lock,
    "Pipfile": parse_pipfile,
    "pyproject.toml": parse_pyproject_toml,
    "Cargo.toml": parse_cargo_toml,
    "go.mod": parse_go_mod,
}

# Patterns tried in order when the exact filename doesn't match.
# Each entry: (suffix_or_name_pattern, parser_function)
FILE_PATTERNS = [
    (lambda n: n.endswith("pom.xml"),         parse_pom_xml),
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


def discover_and_parse(paths: list, skip_dev: bool) -> list:
    all_deps = []
    for p in paths:
        if p.is_dir():
            found_any = False
            for filename in DETECTION_ORDER:
                candidate = p / filename
                if candidate.exists():
                    found_any = True
                    deps = FILE_PARSERS[filename](candidate)
                    console.print(
                        f"  [green]ok[/green] [bold]{candidate}[/bold]  "
                        f"([cyan]{len(deps)}[/cyan] deps)"
                    )
                    all_deps.extend(deps)
            if not found_any:
                console.print(
                    f"[yellow]Warning:[/yellow] No supported manifest found in {p}"
                )
        elif p.is_file():
            parser = _parser_for_file(p)
            if parser is None:
                console.print(f"[yellow]Warning:[/yellow] Unsupported file: {p}")
            else:
                deps = parser(p)
                console.print(
                    f"  [green]ok[/green] [bold]{p}[/bold]  "
                    f"([cyan]{len(deps)}[/cyan] deps)"
                )
                all_deps.extend(deps)
        else:
            console.print(f"[red]Error:[/red] Path not found: {p}")

    if skip_dev:
        before = len(all_deps)
        all_deps = [d for d in all_deps if not d.is_dev]
        skipped = before - len(all_deps)
        if skipped:
            console.print(f"  [dim]Skipped {skipped} dev dependencies[/dim]")

    # Deduplicate by (ecosystem, name, version)
    seen: set = set()
    unique = []
    for dep in all_deps:
        key = (dep.ecosystem, dep.name, dep.version)
        if key not in seen:
            seen.add(key)
            unique.append(dep)
    return unique


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


def query_osv(deps: list) -> dict:
    """
    Two-phase OSV query with a 2-day disk cache.
      Phase 1 — batch query to get vuln IDs for deps not in cache.
      Phase 2 — parallel fetch of full vuln records for new unique IDs.
    Returns {dep_index: [Vulnerability, ...]}.
    """
    results: dict = {i: [] for i in range(len(deps))}
    if not deps:
        return results

    cache = _load_cache()
    now = time.time()
    expires_at = now + CACHE_TTL

    # Split deps into cache hits and misses
    uncached_indices: list = []
    cache_hits = 0
    for i, dep in enumerate(deps):
        key = _cache_key(dep)
        entry = cache.get(key)
        if entry and entry.get("expires", 0) > now:
            results[i] = _vulns_from_cache(entry)
            cache_hits += 1
        else:
            uncached_indices.append(i)

    if cache_hits:
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
                console.print(f"[red]OSV API error:[/red] {e}")
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
    for dep_idx, ids in dep_vuln_ids.items():
        vulns: list = []
        for vid in ids:
            detail = vuln_details.get(vid)
            if not detail:
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
        key = _cache_key(deps[dep_idx])
        cache[key] = {"expires": expires_at, "vulns": _vulns_to_cache(vulns)}
        cache_dirty = True

    if cache_dirty:
        _save_cache(cache)

    return results


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------


def severity_text(sev: str) -> Text:
    return Text(sev, style=SEVERITY_COLORS.get(sev, "dim"))


def print_table_output(deps: list, vuln_map: dict, min_severity: str) -> int:
    min_order = SEVERITY_ORDER.get(min_severity.upper(), 4)

    vulnerable = []
    for idx, dep in enumerate(deps):
        vulns = [
            v
            for v in vuln_map.get(idx, [])
            if SEVERITY_ORDER.get(v.severity, 4) <= min_order
        ]
        if vulns:
            vulns.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 4))
            vulnerable.append((dep, vulns))

    if not vulnerable:
        console.print("\n[bold green]No vulnerabilities found![/bold green]")
        return 0

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
                dep.name if i == 0 else "",
                dep.version if i == 0 else "",
                dep.ecosystem if i == 0 else "",
                severity_text(vuln.severity),
                "\n".join(cve_ids),
                vuln.summary,
                vuln.published,
            )

    console.print(table)
    console.print(
        f"\n[bold]Summary:[/bold] [red]{len(vulnerable)}[/red] vulnerable package(s) "
        f"across [cyan]{len(deps)}[/cyan] total dependencies scanned."
    )
    return len(vulnerable)


def print_json_output(deps: list, vuln_map: dict, min_severity: str = "LOW") -> int:
    min_order = SEVERITY_ORDER.get(min_severity.upper(), 4)
    output = []
    for idx, dep in enumerate(deps):
        vulns = [
            v for v in vuln_map.get(idx, [])
            if SEVERITY_ORDER.get(v.severity, 4) <= min_order
        ]
        if vulns:
            output.append(
                {
                    "package": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "source": dep.source_file,
                    "vulnerabilities": [
                        {
                            "id": v.vuln_id,
                            "aliases": v.aliases,
                            "severity": v.severity,
                            "cvss_score": v.cvss_score,
                            "summary": v.summary,
                            "published": v.published,
                        }
                        for v in vulns
                    ],
                }
            )
    print(json.dumps(output, indent=2))
    return len(output)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


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

    args = parser.parse_args()
    scan_paths = [Path(p) for p in args.paths]

    if args.format == "table":
        console.print("[bold]checkdeps[/bold] -- CVE scanner via OSV (https://osv.dev)\n")
        console.print("[dim]Parsing dependency files...[/dim]")

    deps = discover_and_parse(scan_paths, skip_dev=args.skip_dev)

    if not deps:
        console.print("[yellow]No dependencies found to scan.[/yellow]")
        sys.exit(0)

    if args.format == "table":
        console.print(
            f"\n[dim]Querying OSV API for {len(deps)} unique dependencies...[/dim]"
        )

    vuln_map = query_osv(deps)

    if args.format == "json":
        count = print_json_output(deps, vuln_map, min_severity=args.min_severity)
    else:
        count = print_table_output(deps, vuln_map, min_severity=args.min_severity)

    if args.fail_on_vuln and count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
