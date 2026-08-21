# checkdeps

A command-line tool that scans a project's dependency files and checks every declared package against the [OSV](https://osv.dev) vulnerability database, reporting any known CVEs.

## Supported files

| File | Ecosystem |
|---|---|
| `pom.xml` | Maven (Java) |
| `package.json` | npm (Node.js) |
| `requirements.txt` | pip (Python) |
| `Pipfile` / `Pipfile.lock` | Pipenv (Python) |
| `pyproject.toml` | Poetry / PEP 621 (Python) |
| `Cargo.toml` | Cargo (Rust) |
| `go.mod` | Go modules |

## Installation

### Prerequisites

- **Python 3.11 or higher** — [python.org/downloads](https://www.python.org/downloads/)
- **pip** — included with Python

Verify your Python version:

```bash
python --version
```

---

### Option 1 — Global command with pipx (recommended)

[pipx](https://pipx.pypa.io) installs the tool in an isolated environment and makes `checkdeps` available as a global command.

**Install pipx** (if not already installed):

```bash
pip install pipx
```

**Install checkdeps:**

```bash
pipx install --editable path/to/checkdeps
```

After this, `checkdeps` is available from any directory:

```bash
checkdeps path/to/your/project
```

---

### Option 2 — Run directly with pip

If you prefer not to use pipx, install the dependencies and run the script directly:

```bash
cd path/to/checkdeps
pip install -r requirements.txt
python checkdeps.py path/to/your/project
```

---

### Option 3 — Global command without pipx (Windows)

Create a `.cmd` wrapper in a folder on your `PATH` (e.g. `C:\Windows\System32`):

```bat
@echo off
python C:\path\to\checkdeps\checkdeps.py %*
```

Save it as `checkdeps.cmd`. Then `checkdeps` will work from any terminal.

## Usage

```bash
checkdeps                        # scan current directory
checkdeps path/to/project        # scan a directory
checkdeps pom.xml package.json   # scan specific files
```

### Options

| Flag | Description |
|---|---|
| `--min-severity LEVEL` | Only report at or above this level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (default: `LOW`) |
| `--skip-dev` | Ignore dev/test dependencies |
| `--format json` | Machine-readable JSON output |
| `--fail-on-vuln` | Exit with code 1 if any vulnerabilities are found (useful in CI) |
| `--fail-on-unresolved` | Exit with code 1 if any dependency has no resolved version, or any requirement failed to parse |
| `--python-version X.Y` | `python_version` used to evaluate PEP 508 markers (default: this interpreter) |
| `--sys-platform NAME` | `sys_platform` used to evaluate PEP 508 markers (default: this platform) |
| `--marker-env NAME=VALUE` | Any other PEP 508 marker variable; repeatable |
| `--resolve-from-env` | Take exact versions from the installed environment where a requirement does not pin one |

### Examples

```bash
# Only show high-impact findings
checkdeps --min-severity HIGH

# Ignore dev dependencies
checkdeps --skip-dev

# JSON output, only critical issues, exit 1 if found (CI pipeline)
checkdeps --format json --min-severity CRITICAL --fail-on-vuln

# Evaluate environment markers for a Linux / Python 3.11 deployment target
checkdeps --python-version 3.11 --sys-platform linux
```

## How it works

1. **Parse** — reads dependency files and extracts one record per declared package
2. **Resolve** — works out the *exact* version each record refers to, if one is knowable at all
3. **Batch query** — sends every resolved package to the OSV batch API in one request to get a list of vulnerability IDs per package
4. **Parallel fetch** — fetches full vulnerability details for every unique ID in parallel (up to 20 concurrent requests)
5. **Verify** — re-checks each advisory's affected range against the resolved version using PEP 440 comparison, and drops hits the range does not actually cover
6. **Cache** — results are stored in `~/.checkDeps/cache.json` with a 2-day TTL; subsequent runs skip the API for any package+version already cached
7. **Report** — displays a colour-coded table sorted by severity (CRITICAL → HIGH → MEDIUM → LOW), showing the CVE/GHSA ID, summary, and publish date for each finding, followed by anything that could not be matched

## Python dependency parsing

Python requirements are parsed with a real PEP 508 parser (`packaging.requirements.Requirement`), not a regular expression. That means:

- **Extras are metadata, not part of the name or version.** `uvicorn[standard]==0.34.0` is `uvicorn`, extras `[standard]`, version `0.34.0` — the bracket expression never leaks into either field.
- **Names are canonicalised per PEP 503.** `python_jose`, `Python-JOSE` and `python.jose` all match advisories filed against `python-jose`.
- **Versions are compared per PEP 440**, never as strings. `0.34.0` is correctly *outside* `<0.11.7`; a string comparison would put it inside.
- **Environment markers are evaluated** against the scan target. `colorama==0.4.6; sys_platform == "win32"` is skipped, not reported, on a Linux target.
- **`-r` and `-c` directives are followed** recursively with cycle detection, line-continuations are joined, and `--hash=` options are stripped before parsing. Constraint files pin versions but are not themselves reported as dependencies.

### Unresolved versions

A version is only reported when it is actually known — from an exact `==` / `===` pin, a lockfile, a constraint pin, an immutable wheel/sdist URL, or (with `--resolve-from-env`) the installed environment.

A range (`fastapi>=0.115,<1`), a wildcard (`==1.2.*`), a compatible release (`~=1.2`), a mutable VCS reference or a bare unpinned name names **no single version**. Those records are reported in an *Unresolved versions* section with `vulnerability_match: indeterminate`, and are never sent to OSV. No placeholder version is ever substituted — a fabricated `0.0.0` sits below every `< X` affected range and turns every advisory into a false positive.

Requirements that fail to parse are reported as errors with their file and line number, and no dependency record is emitted for them.

### JSON output

`--format json` prints an object:

```json
{
  "scanned": 4,
  "findings":   [ { "package": "...", "extras": [], "resolved_version": "...", "vulnerabilities": [] } ],
  "unresolved": [ { "package": "...", "vulnerability_match": "indeterminate" } ],
  "skipped":    [ { "package": "...", "marker": "...", "vulnerability_match": "skipped" } ],
  "errors":     [ { "kind": "parse_error", "source": "...", "line": 9 } ]
}
```

## Tests

```bash
pip install -e ".[test]"
pytest
```

## Data source

All vulnerability data comes from the [OSV API](https://osv.dev) — free, no API key required, backed by the GitHub Advisory Database, NVD, and other sources.

## Cache

Results are cached at `~/.checkDeps/cache.json` with a 2-day TTL. The cache key is `ecosystem::package::version`, so changing a version always triggers a fresh lookup.

To clear the cache manually:

```bash
del %USERPROFILE%\.checkDeps\cache.json   # Windows
rm ~/.checkDeps/cache.json                # macOS / Linux
```
