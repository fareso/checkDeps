# CheckDeps Specification — Native Dependency Resolution and Platform-Aware Tool Installation Help

## 1. Purpose

CheckDeps should resolve the dependency graph that a project actually uses instead of relying only on dependency declarations such as:

```text
requests>=2.33.0
react@^19
```

or Maven dependencies without explicit versions.

For every ecosystem supported by CheckDeps, the application should prefer the ecosystem's native package manager, build tool, resolver, or authoritative lockfile when available.

If the required external tool is missing, CheckDeps must display an actionable installation message adapted to the operating system and package managers available on the machine.

Static dependency-file parsing remains as a fallback.

---

## 2. Core Principles

### 2.1 Native resolution first

> The manifest describes intent.  
> The native resolver or lockfile describes the dependency graph actually selected.

Examples:

- Maven should resolve `pom.xml`.
- Gradle should resolve Gradle dependency graphs.
- npm/pnpm/Yarn should resolve JavaScript dependencies.
- Python tooling such as uv/pip/Poetry/Pipenv should resolve Python dependencies.
- Other supported ecosystems should follow the same pattern.

### 2.2 Static parsing remains available

If native resolution cannot be performed, CheckDeps must continue scanning using its existing parsers.

The scan should not fail merely because an optional external resolver is unavailable.

### 2.3 Missing tools must produce useful help

A message such as:

```text
mvn not found
```

is insufficient.

CheckDeps must explain:

- which tool is missing;
- why it is needed;
- what functionality will be lost without it;
- how to install it on the current platform;
- whether a fallback scan will continue.

---

## 3. Scope

This specification applies to every dependency ecosystem registered as supported by CheckDeps.

The implementation must not depend on a hard-coded list duplicated across the application.

Each ecosystem should register a resolver profile containing:

```text
ecosystem
manifest patterns
lockfile patterns
native resolver candidates
required tools
static parser
OSV ecosystem mapping
tool-installation metadata
```

When support for a new ecosystem is added, native-resolution metadata should be added at the same time where a native resolver exists.

---

## 4. Architecture

```text
                         CheckDeps
                             |
                    Project Discovery
                             |
           +-----------------+-----------------+
           |                                   |
       Manifests                           Lockfiles
           |                                   |
           +-----------------+-----------------+
                             |
                     Resolver Registry
                             |
     +-----------------------+-----------------------+
     |                       |                       |
Native Tool Resolver    Lockfile Resolver       Static Parser
     |                       |                       |
     +-----------------------+-----------------------+
                             |
                  ResolvedDependency[]
                             |
                   Normalize + Deduplicate
                             |
                            OSV
```

---

## 5. Resolver Registry

Every supported ecosystem should expose a resolver profile.

Conceptual example:

```python
ResolverProfile(
    ecosystem="Maven",
    manifests=["pom.xml"],
    lockfiles=[],
    resolvers=[
        MavenWrapperResolver(),
        MavenResolver(),
    ],
    static_parser=MavenPomParser(),
    osv_ecosystem="Maven",
)
```

Python:

```python
ResolverProfile(
    ecosystem="PyPI",
    manifests=[
        "pyproject.toml",
        "requirements.txt",
    ],
    lockfiles=[
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
    ],
    resolvers=[
        UvResolver(),
        PoetryResolver(),
        PipenvResolver(),
        PipResolver(),
    ],
    static_parser=PythonStaticParser(),
    osv_ecosystem="PyPI",
)
```

JavaScript:

```python
ResolverProfile(
    ecosystem="npm",
    manifests=["package.json"],
    lockfiles=[
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    ],
    resolvers=[
        NpmResolver(),
        PnpmResolver(),
        YarnResolver(),
    ],
    static_parser=PackageJsonParser(),
    osv_ecosystem="npm",
)
```

---

## 6. Resolver Selection

Resolver selection should follow the most authoritative available source.

General priority:

```text
1. Project-specific wrapper
2. Project-selected package manager
3. Lockfile-aware native resolver
4. Compatible globally installed native tool
5. Deterministic lockfile parsing
6. Static manifest parser
```

Example:

```text
pom.xml
  |
  +-- mvnw.cmd exists
  |      -> use Maven Wrapper
  |
  +-- global mvn exists
  |      -> use Maven
  |
  +-- otherwise
         -> static pom.xml parser
```

The exact order may differ by ecosystem.

---

## 7. Normalized Dependency Model

All resolvers should return the same normalized representation.

Suggested model:

```python
ResolvedDependency(
    ecosystem="Maven",
    name="org.springframework:spring-web",
    version="7.0.4",
    direct=False,
    scope="compile",
    source="backend/pom.xml",
    resolver="maven",
    introduced_by="org.springframework.boot:spring-boot-starter-web",
)
```

Minimum required fields:

```text
ecosystem
name
version
direct
source
resolver
```

Recommended optional fields:

```text
scope
introduced_by
dependency_path
workspace/module
type
classifier
```

---

# 8. Ecosystem Behaviour

## 8.1 Maven

Preferred order:

```text
mvnw.cmd / mvnw
global mvn
static POM parser
```

Maven should resolve:

- parent POM inheritance;
- BOMs;
- dependencyManagement;
- Maven properties;
- direct dependencies;
- transitive dependencies;
- conflict resolution;
- scopes;
- exact selected versions.

CheckDeps should scan the versions selected by Maven.

---

## 8.2 Gradle

Preferred order:

```text
gradlew.bat / gradlew
global gradle
static Gradle parser
```

The wrapper must be preferred over a global Gradle installation.

CheckDeps should ask Gradle for its resolved dependency graph rather than attempting to evaluate arbitrary Gradle build logic itself.

It should capture:

- direct dependencies;
- transitive dependencies;
- selected versions;
- version conflict resolution;
- configurations/scopes where practical.

---

## 8.3 Python

Python resolution should prefer the package manager selected by the project.

Potential resolvers include:

```text
uv
pip
Poetry
Pipenv
```

The exact list should correspond to Python project formats already supported by CheckDeps.

### uv

When `uv.lock` is present and uv is the project manager, prefer uv's structured dependency metadata.

### pip

If a suitable environment exists, CheckDeps may inspect installed packages.

If no environment exists, CheckDeps should prefer a resolver/report mode that can calculate exact dependency versions without modifying the user's environment.

CheckDeps must not install or upgrade project packages merely to scan them.

### Poetry

When a Poetry project is detected, use Poetry-aware dependency resolution where possible.

### Pipenv

When a Pipenv project is detected, use Pipenv-aware resolution where possible.

### Python fallback

If the required resolver is unavailable:

```text
static parsing
```

must remain available.

Dependencies that cannot be assigned an exact version remain indeterminate.

---

## 8.4 JavaScript / TypeScript

CheckDeps should identify the package manager selected by the project.

Detection should consider:

```text
packageManager field in package.json
lockfile type
workspace metadata
```

Potential resolvers include:

```text
npm
pnpm
Yarn
```

### npm

Use npm and/or its lockfile to obtain:

- exact versions;
- direct dependencies;
- transitive dependencies;
- dependency tree.

### pnpm

Use pnpm-aware resolution for projects using `pnpm-lock.yaml`.

### Yarn

Use Yarn-aware resolution for Yarn projects.

CheckDeps must not assume that all Yarn project generations have identical behaviour.

### JavaScript fallback

If the selected package manager is unavailable and the lockfile cannot be safely interpreted:

```text
package.json static parser
```

is used.

---

## 8.5 All Other Supported Ecosystems

Every other ecosystem supported by CheckDeps must follow the same contract:

```text
manifest detected
      |
      v
resolver profile
      |
      +-- native resolution available
      |       |
      |       v
      |    exact graph
      |
      +-- unavailable
              |
              v
         static fallback
```

The architecture must allow new resolvers to be added without changes to the OSV scanning layer.

---

# 9. External Tool Detection

A resolver may depend on an external executable.

Examples:

```text
mvn
gradle
uv
python
poetry
pipenv
npm
pnpm
yarn
```

CheckDeps must determine whether the required command is available before attempting resolution.

Use platform-safe executable discovery.

Conceptually:

```python
shutil.which(command)
```

Project-local wrappers should be checked separately.

---

# 10. Missing Tool Error

A missing external tool must produce a structured, actionable warning.

Bad:

```text
mvn not found
```

Required style:

```text
Maven is not installed.

CheckDeps uses Maven to resolve the exact versions selected by pom.xml,
including BOM-managed and transitive dependencies.

Windows detected.

Install Maven with:
  <platform-specific command>

Then rerun:
  checkdeps .\backend

Continuing with static pom.xml analysis.
Some dependency versions may remain indeterminate.
```

The message must contain:

1. human-readable tool name;
2. command name;
3. reason the tool is needed;
4. detected platform;
5. recommended installation action;
6. rerun instruction;
7. fallback behaviour.

---

# 11. Platform Detection

At minimum distinguish:

```text
Windows
macOS
Linux
```

Suggested detection:

```python
if sys.platform == "win32":
    platform = WINDOWS
elif sys.platform == "darwin":
    platform = MACOS
elif sys.platform.startswith("linux"):
    platform = LINUX
else:
    platform = OTHER
```

---

# 12. Windows Installation Help

On Windows, CheckDeps should detect available package managers.

Recommended candidates:

```text
winget
choco
scoop
```

Selection flow:

```text
winget available?
    |
    +-- yes -> use winget instructions
    |
choco available?
    |
    +-- yes -> use Chocolatey instructions
    |
scoop available?
    |
    +-- yes -> use Scoop instructions
    |
otherwise
    -> generic official installation guidance
```

CheckDeps should normally show only the preferred applicable command.

It should not dump three or four alternative installation methods unless verbose help is requested.

---

# 13. macOS Installation Help

On macOS:

```text
brew available?
    |
    +-- yes -> use Homebrew command
    |
otherwise
    -> generic official/manual installation guidance
```

If another supported package manager is detected in future, it may be registered in the platform installer registry.

---

# 14. Linux Installation Help

Linux help should depend on the actual distribution/package manager when possible.

CheckDeps should inspect:

```text
/etc/os-release
```

and executable availability.

Potential package managers:

```text
apt
apt-get
dnf
yum
pacman
zypper
apk
```

Examples of environments to distinguish:

```text
Debian / Ubuntu
Fedora / RHEL family
Arch
openSUSE
Alpine
```

Do not guess the distribution if it cannot be determined.

If no supported installer is detected, provide generic official installation guidance.

---

# 15. Package Manager Availability

CheckDeps must not blindly recommend another tool that is itself missing.

Bad:

```text
Install Maven:
  brew install maven
```

when Homebrew is not installed.

Better:

```text
Maven is required for full dependency resolution.

macOS detected, but Homebrew was not found.

Install Maven using your preferred macOS package manager or the
official Maven distribution, then rerun CheckDeps.
```

---

# 16. Tool Installation Registry

Installation instructions should not be scattered through resolver code.

Introduce a central registry.

Conceptual model:

```python
ToolDefinition(
    id="maven",
    display_name="Maven",
    executables=["mvn"],
    homepage="official Maven installation page",
    installers={
        WINDOWS_WINGET: InstallInstruction(...),
        WINDOWS_CHOCO: InstallInstruction(...),
        WINDOWS_SCOOP: InstallInstruction(...),
        MACOS_BREW: InstallInstruction(...),
        DEBIAN_APT: InstallInstruction(...),
        FEDORA_DNF: InstallInstruction(...),
        ARCH_PACMAN: InstallInstruction(...),
    },
)
```

Resolvers reference tools by ID:

```python
MavenResolver.required_tools = ["maven"]
```

This prevents duplicate messages and makes installation guidance reusable.

---

# 17. Installation Command Validation

Installation commands are user-facing code and must be treated as maintained data.

Requirements:

- commands must come from the tool registry;
- do not construct commands from arbitrary package names;
- package IDs should be explicit;
- platform/package-manager combinations must be tested;
- outdated installer mappings should be easy to update centrally.

If CheckDeps cannot confidently provide a package-manager command, it should prefer generic official guidance rather than guessing.

---

# 18. Structured Missing-Tool Result

Resolver code should not print messages directly.

Suggested result:

```python
MissingTool(
    tool_id="maven",
    command="mvn",
    resolver="maven",
    project="backend/pom.xml",
    required_for="resolved Maven dependency graph",
)
```

The CLI/UI layer should render the platform-aware message.

Benefits:

- easier testing;
- reusable output;
- future JSON output;
- future IDE integration;
- no platform logic inside dependency resolvers.

---

# 19. Fallback Behaviour

Missing native tools should not abort the entire scan by default.

Example:

```text
Maven not available.
Using static pom.xml analysis.

  ok backend\pom.xml
     14 declared dependencies
     10 versions indeterminate
```

Other project ecosystems should still be scanned normally.

---

# 20. Strict Resolution Mode

A future or optional mode may require native resolution:

```text
--require-native-resolution
```

In this mode, a missing required tool should result in a non-zero exit code.

Example:

```text
ERROR: Maven is required for native Maven resolution but is not installed.
```

Default behaviour remains fallback-friendly.

---

# 21. No Automatic Installation

CheckDeps must **not automatically install missing external tools**.

It may:

- detect them;
- explain why they are required;
- provide installation instructions.

It must not execute:

```text
winget install ...
brew install ...
apt install ...
npm install -g ...
```

without an explicit future feature and explicit user approval.

This specification requires guidance only.

---

# 22. Wrapper Preference

Project-local wrappers should normally avoid missing-tool errors for the global tool.

Examples:

```text
mvnw.cmd
mvnw
gradlew.bat
gradlew
```

If a valid project wrapper exists, CheckDeps should use it even if:

```text
mvn
gradle
```

are absent from `PATH`.

This improves reproducibility.

---

# 23. Tool Version Detection

When a native tool is available, CheckDeps may detect its version.

Example diagnostics:

```text
Maven detected: Apache Maven 3.9.x
Resolver: .\mvnw.cmd
```

Version checks may be required when a resolver depends on functionality introduced in a particular version.

If the installed tool is too old, CheckDeps should treat this differently from a missing tool.

Example:

```text
pnpm 7.x detected, but this resolver requires pnpm >= 9.

Upgrade pnpm with:
  <platform-aware instruction>

Continuing with lockfile/static analysis.
```

---

# 24. Missing vs Unsupported vs Too Old

Tool failures should have distinct categories:

```text
TOOL_NOT_FOUND
TOOL_VERSION_TOO_OLD
TOOL_EXECUTION_FAILED
RESOLUTION_FAILED
OUTPUT_INVALID
TIMEOUT
```

These categories should not be collapsed into a generic error.

---

# 25. Platform-Aware Message Examples

## 25.1 Windows

```text
Maven is required for full Maven dependency resolution.

Windows detected.
winget detected.

Install Maven:
  <registered winget Maven command>

Then rerun:
  checkdeps .\backend

CheckDeps will continue using static pom.xml analysis for this scan.
```

---

## 25.2 macOS

```text
pnpm is required to resolve this pnpm project.

macOS detected.
Homebrew detected.

Install pnpm:
  <registered Homebrew pnpm command>

Then rerun:
  checkdeps .

CheckDeps will continue using package.json/lockfile fallback analysis.
```

---

## 25.3 Ubuntu/Debian

```text
Gradle is required for full Gradle dependency resolution.

Linux detected: Ubuntu.
APT detected.

Install Gradle using the registered Ubuntu/APT guidance.

Then rerun:
  checkdeps .

CheckDeps will continue using static Gradle analysis.
```

---

## 25.4 Unknown Linux

```text
Poetry is required to resolve this Python project.

Linux detected, but no supported system package manager was identified.

Install Poetry using its official installation instructions and rerun:

  checkdeps .

CheckDeps will continue using static pyproject.toml analysis.
```

---

# 26. Output Behaviour

Normal output should remain concise.

Example:

```text
Parsing dependency files...

  Maven: backend\pom.xml
    resolver: Maven Wrapper
    63 resolved dependencies

  npm: frontend\package.json
    resolver: npm
    418 resolved dependencies
```

If a tool is missing:

```text
  Python: service\pyproject.toml
    warning: uv not found
    using static fallback
```

Installation help may be shown immediately below the warning.

---

# 27. Verbose Output

With:

```text
--verbose
```

show:

```text
Resolver selection
Tool executable
Tool version
Platform
Detected package manager
Resolution command
Fallback reason
Direct/transitive counts
```

Sensitive credentials, repository tokens, environment secrets, or authenticated URLs must not be printed.

---

# 28. JSON Output Compatibility

If CheckDeps supports or later adds JSON output, missing-tool help must be structured.

Example:

```json
{
  "type": "missing_tool",
  "tool": "maven",
  "displayName": "Maven",
  "platform": "windows",
  "installer": "winget",
  "fallbackUsed": true
}
```

Human-readable command/help text may be generated by the presentation layer.

---

# 29. Security

Native package/build tools may execute project-controlled logic.

Requirements:

- execute the minimum resolver/inspection operation necessary;
- do not run build/test/package/install lifecycle tasks unless required;
- avoid `shell=True` where possible;
- pass arguments as lists;
- use bounded timeouts;
- capture stdout/stderr;
- do not expose secrets;
- do not automatically install missing tools;
- support a future static-only/safe mode.

Project-local wrappers must be treated as executable project content.

This should be documented clearly.

---

# 30. Process Execution

Suggested execution pattern:

```python
subprocess.run(
    command,
    cwd=project_dir,
    capture_output=True,
    text=True,
    timeout=resolver_timeout,
    check=False,
)
```

Requirements:

- support paths containing spaces;
- support Windows/macOS/Linux;
- clean temporary files;
- avoid command injection;
- preserve project working-directory expectations.

---

# 31. Dependency Deduplication

Before OSV lookup, dependencies should be deduplicated by:

```text
ecosystem
package
exact version
```

Example:

```text
npm
react
19.1.1
```

The application should retain all project/module/source locations even when the OSV query itself is deduplicated.

---

# 32. Direct and Transitive Dependencies

Native resolution should include transitive dependencies whenever the ecosystem resolver exposes them.

This is required for vulnerability scanning.

A vulnerability may exist only in:

```text
application
  -> direct dependency
     -> vulnerable transitive dependency
```

CheckDeps must scan the dependency actually present in the resolved graph.

---

# 33. Dependency Paths

Where the native resolver exposes dependency provenance, preserve it.

Example:

```text
frontend
  -> axios@1.6.0
     -> follow-redirects@1.15.4
```

This may later allow CheckDeps to explain:

```text
Vulnerable transitive dependency:
  follow-redirects@1.15.4

Introduced by:
  axios@1.6.0
```

Dependency-path presentation is recommended but not mandatory for the first implementation.

---

# 34. Tests — Platform Detection

Unit tests must cover:

- Windows;
- macOS;
- Linux;
- unknown platform;
- `/etc/os-release` parsing;
- package manager detection;
- package manager unavailable;
- multiple package managers available;
- deterministic installer preference.

---

# 35. Tests — Missing Tool Help

For every registered external tool, tests should verify:

- tool not found;
- correct display name;
- correct resolver reason;
- correct platform;
- appropriate installer selection;
- generic fallback when installer unknown;
- rerun instruction;
- static fallback message;
- no automatic installation.

---

# 36. Tests — Resolver Behaviour

Tests should cover:

- wrapper preferred to global executable;
- global executable used when wrapper absent;
- missing executable;
- executable too old;
- resolver timeout;
- resolver non-zero exit;
- malformed resolver output;
- dependency deduplication;
- direct/transitive classification;
- fallback parser execution;
- continued scanning of unrelated ecosystems after one resolver fails.

---

# 37. Registry Validation Tests

At startup or in the test suite, validate that every supported ecosystem has:

```text
static parser
OSV mapping
resolver profile
fallback definition
```

For every resolver requiring an external tool, validate that the tool exists in the central tool registry.

This prevents partially implemented ecosystem support.

---

# 38. Acceptance Criteria

The feature is complete when:

- [ ] Every CheckDeps-supported ecosystem uses the common resolver architecture.
- [ ] Native resolution is preferred where supported.
- [ ] Project-specific wrappers are preferred over global tools.
- [ ] Direct dependencies can be resolved to exact versions when the native tool supports it.
- [ ] Transitive dependencies are included where the native tool exposes them.
- [ ] OSV queries use exact resolved versions.
- [ ] Static parsing remains available as fallback.
- [ ] Missing external tools produce actionable help.
- [ ] Installation help depends on the current operating system.
- [ ] Windows installation help detects available package managers.
- [ ] macOS installation help detects Homebrew or uses generic guidance.
- [ ] Linux installation help detects distro/package manager where possible.
- [ ] CheckDeps never recommends a package-manager command without validating the relevant installer strategy.
- [ ] CheckDeps does not automatically install external tools.
- [ ] Missing-tool messages explain why the tool matters.
- [ ] Missing tools do not abort the scan by default.
- [ ] Tool/version/execution failures have distinct internal error categories.
- [ ] Tests cover resolver selection and platform-aware installation messages.
- [ ] Adding a new ecosystem does not require changes to the OSV scanning layer.

---

# 39. Non-Goals

This feature does not require CheckDeps to:

- automatically install package managers;
- automatically modify dependency files;
- automatically upgrade vulnerable packages;
- run full builds;
- run project tests;
- reproduce every package manager's resolver internally;
- replace native package managers;
- guarantee dependency resolution when private repositories are inaccessible.

---

# 40. Future Work

Potential follow-up features:

### Automatic remediation suggestions

Use dependency provenance to identify which direct dependency controls a vulnerable transitive package.

### Native update commands

Example conceptual output:

```text
This vulnerable package is controlled by the Spring Boot BOM.
Consider upgrading the Spring Boot parent.
```

### SBOM

Reuse resolved graphs to generate:

```text
CycloneDX
SPDX
```

### Interactive installation

A future opt-in feature could ask permission before installing a missing resolver tool.

This is explicitly outside the current scope.

### Resolver health command

Potential command:

```text
checkdeps doctor
```

Example:

```text
Maven     OK
Gradle    wrapper available
Python    OK
uv        missing
npm       OK
pnpm      missing
Yarn      missing
```

with platform-aware installation help.

---

# 41. Design Rule

The overall design rule is:

> Ask each ecosystem's native tooling what dependencies are actually resolved.  
> When that tooling is unavailable, explain exactly how to install it on the current platform and continue with the safest available fallback.

This behaviour should be consistent across every language and package ecosystem supported by CheckDeps.
