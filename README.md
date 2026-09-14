# checkdeps

A command-line tool that resolves a project's real dependency graph — asking Maven, Gradle, npm, uv, Cargo or Go what they actually selected, transitive packages included — and checks every resolved package against the [OSV](https://osv.dev) vulnerability database, reporting any known CVEs.

## Supported files

| File | Ecosystem | Resolved by |
|---|---|---|
| `pom.xml` | Maven (Java) | Maven, wrapper first |
| `build.gradle` / `build.gradle.kts` | Gradle (Java) | Gradle, wrapper first |
| `package.json` | npm (Node.js) | `package-lock.json`, `yarn.lock`, or pnpm |
| `requirements.txt` | pip (Python) | static analysis |
| `Pipfile` / `Pipfile.lock` | Pipenv (Python) | `Pipfile.lock` |
| `pyproject.toml` | Poetry / uv / PEP 621 (Python) | `poetry.lock` or `uv.lock` |
| `Cargo.toml` | Cargo (Rust) | `Cargo.lock` or `cargo metadata` |
| `go.mod` | Go modules | `go list -m all` |

Every ecosystem is resolved by its own tooling where that is possible, and parsed statically where it is not — see [Native dependency resolution](#native-dependency-resolution).

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
| `--verbose` | Show the resolved dependency graph, the resolver, tool and platform used, and a tool's own output when resolution fails |
| `--no-native` | Never execute project build tooling; analyse manifests statically |
| `--offline` | Ask native resolvers not to reach the network |
| `--require-native-resolution` | Exit 1 when an ecosystem's native resolver could not run |
| `--resolver-timeout SECONDS` | Time budget for one native resolution (default: 300) |
| `-r`, `--recurse` | Also scan every subdirectory for manifests (skips `node_modules`, `.git`, build output and virtual environments) |
| `--clear-cache` | Delete the local vulnerability cache and exit |
| `--version` | Show the installed checkdeps version and exit |

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

# Show the full dependency graph that was resolved and scanned
checkdeps ./backend --verbose

# CI: fail if a build tool is missing rather than scanning a partial graph
checkdeps --require-native-resolution --fail-on-vuln
```

## How it works

1. **Discover** — finds each ecosystem present in the scanned directories and picks the most authoritative resolver available for it
2. **Resolve** — asks the project's own tooling or lockfile for the graph it actually resolves, falling back to parsing the manifest; either way a version is reported only when it is exactly known
3. **Deduplicate** — one OSV query per ecosystem/package/version, however many modules use it
4. **Batch query** — sends every resolved package to the OSV batch API in one request to get a list of vulnerability IDs per package
5. **Parallel fetch** — fetches full vulnerability details for every unique ID in parallel (up to 20 concurrent requests)
6. **Verify** — re-checks each advisory's affected range against the resolved version using PEP 440 comparison, and drops hits the range does not actually cover
7. **Cache** — results are stored in `~/.checkDeps/cache.json` with a 2-day TTL; subsequent runs skip the API for any package+version already cached
8. **Report** — displays a colour-coded table sorted by severity (CRITICAL → HIGH → MEDIUM → LOW), showing the CVE/GHSA ID, summary, and publish date for each finding, followed by anything that could not be matched

## Native dependency resolution

A manifest states intent. `requests>=2.33.0`, `"react": "^19"` and a `<dependency>` with no `<version>` all name a *range*, a *parent POM* or *nothing at all* — never the artifact that ends up running. And most of what runs was never named in the manifest at all: it arrived transitively.

So for every ecosystem, checkdeps asks the thing that actually knows:

| Ecosystem | Asked first | Then | Fallback |
|---|---|---|---|
| Maven | `mvnw` / `mvnw.cmd` wrapper | `mvn` on `PATH` | static `pom.xml` |
| Gradle | `gradlew` / `gradlew.bat` wrapper | `gradle` on `PATH` | static `build.gradle` |
| npm / Yarn / pnpm | the `packageManager` field's tool | `package-lock.json`, `yarn.lock`, `pnpm` | static `package.json` |
| Python | `uv.lock`, `poetry.lock`, `Pipfile.lock` | — | static `requirements.txt` / `pyproject.toml` / `Pipfile` |
| Rust | `Cargo.lock` | `cargo metadata` | static `Cargo.toml` |
| Go | `go list -m -json all` | — | static `go.mod` |

No flag turns this on. A resolved graph is simply what a project *is*.

```text
  Maven: backend\pom.xml
    resolver: Maven Wrapper
    63 resolved dependencies (14 direct, 49 transitive)

  npm: frontend\package.json
    resolver: package-lock.json
    418 resolved dependencies (12 direct, 406 transitive)
```

- **Project wrappers win.** `mvnw` and `gradlew` pin the version the build was written for, so they are preferred over anything on `PATH`, and searched for up to the reactor root where multi-module builds keep them.
- **Only read-only inspection commands run** — `dependency:tree`, `gradle dependencies`, `pnpm ls`, `npm ls`, `cargo metadata`, `go list`. Never `build`, `test`, `package`, `install` or `publish`. Each runs as an argument list without a shell, in the project's own directory, under a timeout, with its output captured; temporary files are removed on success and failure alike.
- **Lockfiles are read, not re-derived.** `package-lock.json`, `yarn.lock` (both generations), `uv.lock`, `poetry.lock`, `Pipfile.lock` and `Cargo.lock` are already the resolver's own answer, so checkdeps reads them directly — no tool needs to be installed, nothing is installed *into* the project, and the scan cannot change what the project resolves to.
- **The tool's answer is used as-is.** Maven's dependency mediation, Gradle's `3.11 -> 3.12.0` conflict resolution and Go's minimal version selection decide the versions scanned. checkdeps does not re-implement anybody's resolver.
- **Transitive dependencies are scanned too**, with the package that pulled each one in recorded alongside it. A vulnerability usually arrives three levels down; scanning only what the manifest names would miss most of them.
- **Nothing is ever fatal.** A missing tool, an unreachable repository, an unresolvable artifact or a malformed report all produce one warning line and the static reading of the manifest. Other ecosystems in the same scan are unaffected. `--require-native-resolution` inverts that for CI, where a silently degraded scan is worse than a failed one.

Because native resolution executes the project's own build tooling, `--no-native` turns it off entirely and analyses manifests statically.

## When a tool is missing

`mvn not found` is not help. checkdeps explains what is missing, why it mattered, and the one command that fixes it *on the machine you are sitting at*:

```text
  Maven: backend\pom.xml
    warning mvn not found
    resolver: static pom.xml analysis
    14 declared dependencies, 10 versions indeterminate

    Maven is not installed.

    checkdeps uses Maven (mvn) to resolve the exact versions a pom.xml selects,
    including parent-, BOM- and dependencyManagement-supplied versions and the
    whole transitive graph.

    Windows detected, winget detected.

    Install Maven:
      winget install --id Apache.Maven -e

    Then rerun:
      checkdeps .\backend

    Continuing with static pom.xml analysis.
    Some dependency versions may remain indeterminate.
```

- **The package manager has to exist.** Suggesting `brew install maven` to somebody without Homebrew is the same dead end as suggesting nothing, so only managers found on `PATH` are ever named. On Windows that is winget, then Chocolatey, then Scoop; on macOS, Homebrew; on Linux, the distribution's own manager, read from `/etc/os-release` — apt, dnf, pacman, zypper or apk.
- **The distribution is never guessed.** No `/etc/os-release`, or one checkdeps does not recognise, means checkdeps says so and offers the tool's official instructions instead.
- **Commands come from a registry, not from string-building.** Every install command is a maintained entry keyed by tool and package manager. A combination with no entry falls back to a platform-independent command where one genuinely exists (`pipx install poetry`), and to the tool's homepage otherwise. checkdeps would rather say "see the official instructions" than invent a package name.
- **checkdeps never installs anything.** It detects, explains and continues. Running the install command is your decision.
- **A tool that is too old is not a tool that is missing.** Both are reported, in different words, with distinct internal categories (`TOOL_NOT_FOUND`, `TOOL_VERSION_TOO_OLD`, `TOOL_EXECUTION_FAILED`, `RESOLUTION_FAILED`, `OUTPUT_INVALID`, `TIMEOUT`).

Python projects get the same treatment for their lockfiles: a `pyproject.toml` with `[tool.poetry]` and no `poetry.lock` is told to run `poetry lock` — and, if Poetry itself is missing, how to install it first.

With `--format json`, the same facts are structured rather than prose:

```json
{
  "missing_tools": [
    {
      "type": "missing_tool", "tool": "maven", "displayName": "Maven",
      "platform": "windows", "installer": "winget",
      "installCommand": "winget install --id Apache.Maven -e",
      "fallbackUsed": true
    }
  ]
}
```

`--verbose` adds the resolver chosen, the executable, its version, the detected platform and package manager, the exact command run, and the tool's own log when resolution fails. Anything shaped like a credential — a URL with a password, a bearer token, a `-Dpassword=` argument — is masked before it is printed.

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

Natively resolved records additionally carry `resolver`, `direct`, `introduced_by`, `scope`, `type`, `classifier` and `sources` (every manifest the package/version was resolved in). The object also has a `resolution` array — one entry per manifest, naming the resolver used and its counts — and a `missing_tools` array of structured installation help.

## Tests

```bash
pip install -e ".[test]"
pytest
```

## Data source

All vulnerability data comes from the [OSV API](https://osv.dev) — free, no API key required, backed by the GitHub Advisory Database, NVD, and other sources.

## Cache

Results are cached at `~/.checkDeps/cache.json` with a 2-day TTL. The cache key is `ecosystem::package::version`, so changing a version always triggers a fresh lookup.

Expired entries are dropped whenever the cache is written. To clear it completely:

```bash
checkdeps --clear-cache
```
