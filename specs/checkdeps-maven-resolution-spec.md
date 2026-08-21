# CheckDeps Specification — Maven Resolved Dependency Support

## 1. Overview

CheckDeps currently parses `pom.xml` files directly to discover Maven dependencies.

This works for dependencies with explicit versions, but it is incomplete for real-world Maven projects because many versions are inherited or managed through:

- Parent POMs
- `dependencyManagement`
- Imported BOMs
- Spring Boot dependency management
- Maven property substitution
- Transitive dependencies
- Maven conflict resolution / dependency mediation

As a result, CheckDeps may report dependencies as unresolved even though Maven itself can determine the exact versions being used.

This change makes Maven the source of truth for Maven projects whenever Maven is available.

---

## 2. Goal

When CheckDeps detects a Maven project, it should use Maven to resolve the actual dependency graph and scan the exact resolved versions.

The scanner must include:

- Direct dependencies
- Transitive dependencies
- Versions inherited from parent POMs
- Versions supplied by BOMs
- Versions supplied by `dependencyManagement`
- Property-resolved versions
- Maven-selected versions after dependency conflict resolution

The existing static `pom.xml` parser remains available as a fallback when Maven cannot be executed.

---

## 3. Desired User Experience

Given:

```powershell
checkdeps .\backend\
```

and a Maven project containing:

```text
backend\pom.xml
```

CheckDeps should automatically detect and use Maven.

Example output:

```text
checkdeps -- CVE scanner via OSV (https://osv.dev)

Parsing dependency files...
  Maven detected: .\mvnw.cmd
  Resolving backend\pom.xml with Maven...
  ok backend\pom.xml
     14 direct dependencies
     49 transitive dependencies
     63 resolved dependencies

Querying OSV API for 63 resolved dependencies...

No vulnerabilities found!

Summary:
  14 direct dependencies
  49 transitive dependencies
  63 dependencies scanned
  0 indeterminate
  0 vulnerable
```

The user should not need to specify `--resolve-from-env` for normal Maven dependency resolution.

---

## 4. Maven Detection

For each discovered `pom.xml`, CheckDeps should determine whether Maven can be executed.

Detection order:

1. Maven Wrapper local to the project:
   - Windows: `mvnw.cmd`
   - Unix/macOS: `./mvnw`

2. Maven available on `PATH`:
   - `mvn`

The Maven Wrapper MUST be preferred over a globally installed Maven version.

Reason:

The Maven Wrapper represents the Maven version selected by the project and therefore provides more reproducible dependency resolution.

### Example

```text
pom.xml detected
    |
    +-- mvnw.cmd exists?
    |      |
    |      +-- yes -> use mvnw.cmd
    |
    +-- mvnw exists?
    |      |
    |      +-- yes -> use ./mvnw
    |
    +-- mvn available on PATH?
           |
           +-- yes -> use mvn
           |
           +-- no -> use static POM fallback
```

---

## 5. Maven Resolution Strategy

CheckDeps MUST ask Maven for the resolved dependency graph rather than attempting to reproduce Maven dependency management internally.

Preferred implementation:

Use the Maven Dependency Plugin with machine-readable output.

Conceptual invocation:

```text
mvn org.apache.maven.plugins:maven-dependency-plugin:<version>:tree     -DoutputType=json     -DoutputFile=<temporary-file>
```

On Windows with Maven Wrapper:

```text
mvnw.cmd org.apache.maven.plugins:maven-dependency-plugin:<version>:tree ...
```

The command MUST execute with the directory containing the target `pom.xml` as its working directory.

If CheckDeps scans a non-default POM, it MAY also use:

```text
-f <path-to-pom.xml>
```

where appropriate.

---

## 6. Machine-Readable Output

CheckDeps SHOULD use a machine-readable dependency-tree format.

Preferred format:

```text
JSON
```

The scanner SHOULD NOT rely on parsing Maven's standard human-readable console tree unless no structured format is available.

Reasons:

- Human-readable output can vary
- Maven/plugin versions may alter formatting
- Tree prefixes such as `+-`, `\-`, and indentation are fragile to parse
- Structured output is easier to test
- Structured output preserves dependency hierarchy

A fixed Maven Dependency Plugin version MAY be invoked explicitly to ensure support for the required output format.

---

## 7. Resolved Dependency Model

Each resolved Maven dependency should contain at least:

```text
groupId
artifactId
version
scope
type
classifier (optional)
direct/transitive
source pom.xml
```

Suggested internal representation:

```python
ResolvedDependency(
    ecosystem="Maven",
    name="org.springframework:spring-web",
    version="7.0.4",
    scope="compile",
    direct=False,
    source="backend/pom.xml",
)
```

For OSV queries:

```text
ecosystem = Maven
name      = groupId:artifactId
version   = resolved version
```

Example:

```text
org.springframework:spring-web
7.0.4
```

---

## 8. Direct vs Transitive Dependencies

CheckDeps MUST distinguish direct dependencies from transitive dependencies.

### Direct dependency

Explicitly declared by the project.

Example:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

### Transitive dependency

Introduced through another dependency.

Example:

```text
spring-boot-starter-web
  -> spring-web
  -> spring-webmvc
  -> tomcat-embed-core
```

All resolved dependencies SHOULD be scanned for vulnerabilities by default.

A CVE scanner that only scans direct Maven dependencies is insufficient because vulnerable components commonly enter through transitive dependencies.

---

## 9. Maven Dependency Mediation

CheckDeps MUST scan the version actually selected by Maven.

Example dependency graph:

```text
A -> library-x:1.0
B -> library-x:2.0
```

If Maven resolves the final dependency graph to:

```text
library-x:2.0
```

CheckDeps MUST scan:

```text
library-x:2.0
```

and SHOULD NOT treat `1.0` as an installed/resolved dependency unless Maven reports that version as part of the effective dependency graph.

CheckDeps MUST NOT attempt to implement Maven's dependency mediation rules itself.

---

## 10. Parent POM and BOM Resolution

The following dependency MUST no longer be considered unresolved merely because it has no `<version>` element:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

If Maven resolves the version through a parent POM or BOM, CheckDeps MUST use that resolved version.

This applies to:

- Spring Boot parent POMs
- Imported BOMs
- Maven `dependencyManagement`
- Parent project dependency management
- Version properties such as `${spring.version}`
- Multi-module inheritance where Maven can resolve the effective model

---

## 11. Fallback Behaviour

If Maven cannot be executed, CheckDeps MUST fall back to the existing static `pom.xml` parser.

Examples:

- Maven is not installed
- No Maven Wrapper is present
- Maven cannot start
- Dependency plugin execution fails
- The project cannot currently resolve its POM
- Required repositories are unavailable

Example output:

```text
Parsing dependency files...
  warning Maven unavailable for backend\pom.xml
  falling back to static POM analysis
  ok backend\pom.xml (14 deps, 10 unresolved)
```

The fallback MUST NOT cause the entire CheckDeps scan to fail unless the user has explicitly requested strict Maven resolution.

---

## 12. Maven Resolution Failure

If Maven exists but dependency resolution fails, CheckDeps should display a concise explanation.

Example:

```text
Resolving backend\pom.xml with Maven...
  warning Maven dependency resolution failed
  reason: Could not resolve artifact com.example:internal-lib:2.1.0

Falling back to static POM analysis...
```

Verbose Maven output SHOULD only be shown when:

```text
--verbose
```

or a similar diagnostic option is enabled.

CheckDeps SHOULD avoid dumping large Maven logs during normal operation.

---

## 13. Offline and Repository Behaviour

CheckDeps MUST allow Maven to behave according to the project's normal Maven configuration.

This includes:

- `settings.xml`
- Maven local repository
- configured mirrors
- authenticated repositories
- corporate repositories
- Maven Wrapper configuration

CheckDeps SHOULD NOT implement its own Maven repository resolver.

CheckDeps SHOULD NOT require Maven dependencies to already exist locally.

Maven may contact configured repositories as required.

A future `--offline` option MAY execute Maven with:

```text
-o
```

but this is outside the minimum scope of this change.

---

## 14. Multi-Module Maven Projects

CheckDeps SHOULD support Maven multi-module projects.

Example:

```text
project/
  pom.xml
  api/
    pom.xml
  service/
    pom.xml
  persistence/
    pom.xml
```

When scanning the root project, CheckDeps should avoid unnecessarily resolving the same dependency graph multiple times.

Preferred behaviour:

- Detect Maven reactor roots
- Resolve modules using Maven
- Associate dependencies with their originating modules where practical
- Deduplicate identical resolved package/version pairs before OSV requests

The first implementation MAY resolve each discovered POM independently if necessary, but duplicate OSV queries MUST still be deduplicated.

---

## 15. Dependency Deduplication

Before querying OSV, CheckDeps SHOULD deduplicate Maven dependencies by:

```text
ecosystem
package name
resolved version
```

For Maven:

```text
Maven
org.springframework:spring-core
7.0.4
```

If the same resolved dependency appears in multiple modules, it should normally produce one OSV query.

CheckDeps SHOULD retain all source/module references internally for reporting.

Example:

```text
org.springframework:spring-core:7.0.4
  used by:
    backend/api/pom.xml
    backend/service/pom.xml
```

---

## 16. Scope Handling

CheckDeps SHOULD initially include Maven dependencies from commonly deployed/runtime-relevant scopes:

```text
compile
runtime
provided
```

Test dependencies MAY also be scanned.

Existing CheckDeps behaviour should be preserved unless explicitly changed.

The resolved dependency model MUST retain Maven scope so future filtering can be added.

Possible future options:

```text
--include-test
--exclude-test
--scope runtime
```

These options are not required for the initial implementation.

---

## 17. Output Changes

### Existing output

```text
ok backend\pom.xml (14 deps, 10 unresolved)
```

### Desired Maven-resolved output

```text
Maven detected: C:\apache-maven\bin\mvn.cmd
Resolving backend\pom.xml with Maven...
  ok backend\pom.xml
     14 direct
     49 transitive
     63 resolved
```

If Maven Wrapper is used:

```text
Maven detected: backend\mvnw.cmd
```

If static fallback is used:

```text
Maven unavailable
Using static pom.xml analysis
  ok backend\pom.xml (14 deps, 10 unresolved)
```

---

## 18. Verbose Output

With:

```powershell
checkdeps .\backend\ --verbose
```

CheckDeps SHOULD optionally display resolved dependencies.

Example:

```text
DIRECT

org.springframework.boot:spring-boot-starter-web:4.0.3
org.springframework.boot:spring-boot-starter-security:4.0.3
org.postgresql:postgresql:42.7.8

TRANSITIVE

org.springframework:spring-web:7.0.4
org.springframework:spring-webmvc:7.0.4
org.springframework:spring-core:7.0.4
org.apache.tomcat.embed:tomcat-embed-core:11.0.15
...
```

Exact formatting may follow CheckDeps' existing Rich console conventions.

---

## 19. Summary Changes

For Maven-resolved projects, the final summary SHOULD distinguish:

```text
direct dependencies
transitive dependencies
resolved dependencies
indeterminate dependencies
vulnerable dependencies
```

Example:

```text
Summary:
  14 direct dependencies
  49 transitive dependencies
  63 dependencies scanned
  0 indeterminate
  2 vulnerable
```

If CheckDeps combines multiple ecosystems, the existing global summary may remain, but Maven resolution statistics should still be visible during parsing.

---

## 20. CLI Behaviour

### Default

```powershell
checkdeps .
```

Automatically use Maven when a `pom.xml` is detected.

### No additional flag should be required

Maven resolution is not equivalent to Python's:

```text
--resolve-from-env
```

The resolved Maven graph is part of the normal Maven project model and should therefore be automatic.

### Optional future flags

Potential future controls:

```text
--no-maven
--maven-command <path>
--maven-timeout <seconds>
--maven-offline
```

These are not required for the first implementation.

---

## 21. Process Execution Requirements

Maven MUST be invoked safely.

Requirements:

- Use `subprocess` without `shell=True` where possible
- Pass arguments as an argument list
- Use the Maven project directory as `cwd`
- Use a bounded timeout
- Capture stdout/stderr
- Do not interpolate user-controlled paths into shell command strings
- Clean up temporary files
- Support paths containing spaces
- Support Windows, Linux, and macOS

Example conceptual implementation:

```python
subprocess.run(
    command,
    cwd=project_dir,
    capture_output=True,
    text=True,
    timeout=MAVEN_TIMEOUT,
    check=False,
)
```

---

## 22. Temporary Files

If the Maven Dependency Plugin writes JSON to a file:

- Use the OS temporary directory
- Generate unique filenames
- Always remove temporary files after parsing
- Remove them on both success and failure
- Do not write generated dependency files into the user's project tree

---

## 23. Caching

CheckDeps MAY cache Maven-resolved dependency graphs in the future.

Initial implementation does not require graph caching.

Existing OSV response caching MUST continue to work.

Because Maven resolution itself may be relatively expensive, a future cache could use:

```text
pom.xml hash
relevant parent/module POM hashes
Maven command/version
```

as part of the cache key.

This is explicitly outside the minimum implementation scope.

---

## 24. Security Considerations

Executing Maven is different from parsing XML.

Maven builds can load plugins and execute project-defined build logic.

Therefore:

- CheckDeps MUST make it clear that Maven resolution executes Maven tooling for the scanned project.
- CheckDeps SHOULD execute only the minimum Maven goal necessary to obtain dependency information.
- CheckDeps MUST NOT execute lifecycle goals such as:

```text
package
install
verify
test
```

merely to discover dependencies.

The implementation should use dependency inspection goals only.

A future safe/static-only mode MAY disable Maven execution.

---

## 25. Performance

Maven dependency resolution may be slower than static POM parsing.

CheckDeps SHOULD:

- Resolve each Maven project only once per scan where possible
- Deduplicate OSV requests
- Avoid invoking Maven separately for each dependency
- Avoid repeated Maven executions for the same POM
- Continue using the existing OSV cache

Normal Maven console output should be suppressed or captured unless verbose mode is enabled.

---

## 26. Error Classification

Maven-related failures SHOULD be classified internally.

Suggested categories:

```text
MAVEN_NOT_FOUND
MAVEN_TIMEOUT
MAVEN_EXECUTION_FAILED
MAVEN_DEPENDENCY_RESOLUTION_FAILED
MAVEN_OUTPUT_INVALID
MAVEN_PLUGIN_FAILED
```

This makes diagnostics and tests more reliable than matching arbitrary error strings.

---

## 27. Testing Requirements

### Unit tests

Add tests for:

1. Maven executable detection
2. Maven Wrapper preference
3. Windows `mvnw.cmd`
4. Unix `mvnw`
5. Global `mvn`
6. Maven unavailable fallback
7. JSON dependency-tree parsing
8. Direct dependency detection
9. Transitive dependency detection
10. Scope preservation
11. Dependency deduplication
12. Maven failure fallback
13. Temporary file cleanup
14. Paths containing spaces
15. Maven timeout handling

---

## 28. Integration Tests

Create sample Maven projects covering:

### Explicit version

```xml
<dependency>
    <groupId>org.example</groupId>
    <artifactId>library</artifactId>
    <version>1.2.3</version>
</dependency>
```

Expected:

```text
1.2.3 resolved
```

### Parent-managed version

Dependency has no explicit version.

Expected:

```text
version resolved by Maven
```

### BOM-managed version

Expected:

```text
version resolved by Maven
```

### Property version

```xml
<version>${library.version}</version>
```

Expected:

```text
property expanded by Maven
```

### Transitive dependency

Expected:

```text
transitive dependency included in OSV scan
```

### Version conflict

Two paths introduce different versions.

Expected:

```text
only Maven-selected resolved version is scanned
```

### Maven unavailable

Expected:

```text
static parser fallback
```

### Maven execution failure

Expected:

```text
warning + fallback
```

---

## 29. Spring Boot Acceptance Scenario

Given a Spring Boot application with dependencies such as:

```xml
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
```

and versions supplied by Spring Boot dependency management:

### Before

CheckDeps reports:

```text
spring-boot-starter-web       (none)
spring-boot-starter-security  (none)
postgresql                    (none)
```

as unresolved.

### After

CheckDeps MUST resolve concrete versions through Maven and scan them.

It MUST also scan transitive packages including components such as:

```text
spring-web
spring-webmvc
spring-core
spring-security-core
tomcat-embed-core
```

when present in the Maven-resolved graph.

---

## 30. Acceptance Criteria

This feature is complete when all of the following are true:

- [ ] CheckDeps detects Maven projects automatically.
- [ ] Maven Wrapper is preferred over global Maven.
- [ ] CheckDeps invokes Maven without requiring a new CLI flag.
- [ ] Dependencies with versions inherited from parent POMs are resolved.
- [ ] BOM-managed dependency versions are resolved.
- [ ] `${property}` versions are resolved by Maven.
- [ ] Direct dependencies are identified.
- [ ] Transitive dependencies are discovered.
- [ ] Maven-selected conflict-resolved versions are used.
- [ ] Resolved Maven dependencies are queried against OSV.
- [ ] Duplicate Maven package/version OSV queries are avoided.
- [ ] Maven failure falls back to the current static parser.
- [ ] Maven-unavailable environments continue to work.
- [ ] Normal output clearly states whether Maven resolution or static parsing was used.
- [ ] Verbose output can show the resolved dependency list.
- [ ] Tests cover Maven Wrapper, global Maven, fallback, transitive dependencies, BOMs, properties, and version conflicts.
- [ ] Existing non-Maven scanners continue to work unchanged.

---

## 31. Non-Goals

The first version does NOT need to:

- Reimplement Maven's dependency resolver in Python
- Download dependencies directly without Maven
- Execute a complete Maven build
- Run tests
- Package or install the scanned project
- Implement vulnerability remediation
- Modify `pom.xml`
- Implement Gradle resolution

Gradle should be handled as a separate follow-up feature using the same principle:

> Ask the native build tool for the resolved dependency graph instead of attempting to infer it from build files.

---

## 32. Future Work

Potential follow-up improvements:

### Gradle native resolution

Use:

```text
gradlew
```

or:

```text
gradle
```

to obtain the actual dependency graph.

### Dependency provenance

Display paths such as:

```text
spring-boot-starter-web
  -> spring-boot-starter-tomcat
     -> tomcat-embed-core
```

for vulnerable transitive dependencies.

### Vulnerability explanation

Example:

```text
CVE affects:
  org.apache.tomcat.embed:tomcat-embed-core:11.x

Introduced through:
  spring-boot-starter-web
    -> spring-boot-starter-tomcat
      -> tomcat-embed-core
```

### Suggested upgrade path

Use Maven dependency-management information to determine which direct dependency or parent/BOM controls the vulnerable version.

### SBOM support

Resolved Maven dependency graphs could later be reused to generate or consume:

- CycloneDX
- SPDX

---

## 33. Implementation Principle

The core design principle for Maven support is:

> Maven, not the raw `pom.xml`, determines the dependency graph that the application actually uses.

CheckDeps should therefore use Maven's resolved model whenever possible and treat static XML parsing as a fallback only.
