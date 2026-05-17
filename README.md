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

### Examples

```bash
# Only show high-impact findings
checkdeps --min-severity HIGH

# Ignore dev dependencies
checkdeps --skip-dev

# JSON output, only critical issues, exit 1 if found (CI pipeline)
checkdeps --format json --min-severity CRITICAL --fail-on-vuln
```

## How it works

1. **Parse** — reads dependency files and extracts package names and pinned versions, resolving range operators (`^`, `~`, `>=`, etc.) to a concrete version string
2. **Batch query** — sends all packages to the OSV batch API in one request to get a list of vulnerability IDs per package
3. **Parallel fetch** — fetches full vulnerability details for every unique ID in parallel (up to 20 concurrent requests)
4. **Cache** — results are stored in `~/.checkDeps/cache.json` with a 2-day TTL; subsequent runs skip the API for any package+version already cached
5. **Report** — displays a colour-coded table sorted by severity (CRITICAL → HIGH → MEDIUM → LOW), showing the CVE/GHSA ID, summary, and publish date for each finding

## Data source

All vulnerability data comes from the [OSV API](https://osv.dev) — free, no API key required, backed by the GitHub Advisory Database, NVD, and other sources.

## Cache

Results are cached at `~/.checkDeps/cache.json` with a 2-day TTL. The cache key is `ecosystem::package::version`, so changing a version always triggers a fresh lookup.

To clear the cache manually:

```bash
del %USERPROFILE%\.checkDeps\cache.json   # Windows
rm ~/.checkDeps/cache.json                # macOS / Linux
```
