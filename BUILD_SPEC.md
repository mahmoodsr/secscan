# BUILD_SPEC: secscan — Manual Code Security and Quality Scanning

Working name: `secscan` (placeholder, rename freely). Audience: the coding agent that builds this product. Read the whole document before writing code. Where this spec and the agent's habits disagree, this spec wins. Where this spec is silent, choose the simplest option and record the choice in `docs/DECISIONS.md`.

Status: ready for agent. Two milestones. Milestone 2 must not start until Milestone 1's self-test passes.

---

## Problem Statement

Developers deliver code to customers without a consistent security and quality check. Four good open-source tools exist (Semgrep, Gitleaks, Trivy, SonarQube Community Build), but running them means four installs, four command lines, four report formats, four severity scales, and a shared SonarQube server with token handling. Developers will skip it, run it wrongly, or paste secrets into reports. The Tech Lead has no single answer to "is this project safe to deliver?"

## Solution

One command per operating system scans any project directory with all four tools, never stops when one tool breaks, and produces one summary with a clear PASS / FAIL / ERROR per tool, unified severity counts, a list of what must be fixed, the SonarQube Quality Gate result, and a link to the SonarQube dashboard. Reports never contain secret values. A thresholds file, approved by the Tech Lead, decides what blocks delivery. Milestone 2 adds a local glass-style dashboard where a developer presses Run, watches progress, reviews findings, and compares scans before and after fixing.

Milestone 1 is the Phase 1 deliverable. Milestone 2 is a thin layer over Milestone 1: the dashboard starts the command-line engine and reads its output. It never re-implements scanning logic.

---

## Glossary

- **Engine**: the shared Python program that orchestrates tools, normalizes results, applies thresholds, and writes reports.
- **Wrapper**: the thin per-OS entry script (`run-security-scan.ps1`, `run-security-scan.sh`) that checks prerequisites and calls the engine.
- **Tool run**: one execution of Semgrep, Gitleaks, Trivy, or SonarScanner within a scan.
- **Scan**: one full execution over one project directory, producing one set of reports.
- **Finding**: one normalized issue from any tool.
- **Blocking finding**: a finding that matches the approved thresholds and is not allowlisted.
- **Allowlist entry**: an approved exception with reason, owner, and expiry date.
- **Quality Gate**: the pass/fail verdict computed by the central SonarQube server for a project.
- **Self-test**: a built-in command that proves the install works on the current OS.

---

## User Stories

### Developer: running a scan
1. As a developer, I want to run one command from my project root, so that I do not have to remember four tool commands.
2. As a developer, I want to pass a project directory as an argument, so that I can scan a project without changing directory.
3. As a developer, I want the same command shape on Windows and macOS, so that team documentation is simple.
4. As a developer, I want the script to check that all tools are installed and configured before scanning, so that I get clear errors instead of cryptic failures.
5. As a developer, I want missing tools to show the exact install command for my OS, so that I can fix my machine in one step.
6. As a developer, I want the scan to continue when one tool fails, so that I still get results from the other three.
7. As a developer, I want each failed tool to say why it failed (not installed, bad URL, bad token, timeout, crash), so that I know what to fix.
8. As a developer, I want to scan any project type, so that I am never told "unsupported".
9. As a developer, I want unknown project types to still run in a generic mode and tell me which checks were reduced, so that I know the limits of the result.
10. As a developer, I want generated files, dependency folders, and build output excluded automatically, so that results are not drowned in noise.
11. As a developer, I want vulnerability scanning to still see my lockfiles and manifests even though dependency folders are excluded, so that dependency checks are accurate.
12. As a developer, I want a `--no-fail` option, so that I can run a scan for information without failing my own scripts.
13. As a developer, I want a clear progress line per tool in the terminal, so that I know the scan is not stuck.
14. As a developer, I want a hard timeout per tool, so that one hung tool cannot block the whole scan forever.
15. As a developer, I want an optional `--build` flag for Java and .NET projects, so that deeper analysis is possible when I choose it.
16. As a developer, I want a warning when Java or .NET analysis is reduced because the project is not built, so that I understand a clean result may be shallow.

### Developer: results
17. As a developer, I want all outputs in a `scan-reports/` folder inside the project, so that I always know where to look.
18. As a developer, I want one summary with overall status, so that I can see in seconds whether I can deliver.
19. As a developer, I want PASS, FAIL, or ERROR per tool, so that a crashed tool is never mistaken for a clean tool.
20. As a developer, I want finding counts by unified severity (Critical, High, Medium, Low, Info), so that tools are comparable.
21. As a developer, I want a "must fix" list with file, line, rule, and short fix guidance, so that I know what to do next.
22. As a developer, I want the SonarQube Quality Gate verdict, not just "the scanner finished", so that the result reflects the server's judgment.
23. As a developer, I want a link to the SonarQube dashboard for my project, so that I can drill in.
24. As a developer, I want the summary to show project name, scan date, and commit or version, so that a report can be matched to a delivery.
25. As a developer, I want the summary in HTML, Markdown, and JSON, so that I can read it, commit-review it, or feed it to other tools.
26. As a developer, I want the raw per-tool reports kept (redacted), so that I can dig into tool-specific detail.
27. As a developer, I want `scan-reports/` to be git-ignored automatically, so that reports never leak into customer code.
28. As a developer, I want to rescan after fixing and see the status improve, so that I can prove the fix worked.

### Developer: secrets and safety
29. As a developer, I want detected secrets never printed or saved in any report, so that sharing a report cannot leak a credential.
30. As a developer, I want the SonarQube token read from an environment variable or secure store, so that it is never in a script or repository.
31. As a developer, I want my own personal SonarQube token, so that scans are attributable and one leak does not affect everyone.
32. As a developer, I want a clear message when the token is missing, expired, or lacks permission, so that I can request the right access.
33. As a developer, I want the scan to not send telemetry from Semgrep, so that customer code context stays inside the company.

### Tech Lead
34. As a Tech Lead, I want blocking thresholds in one reviewable document, so that I can approve or change policy in one place.
35. As a Tech Lead, I want thresholds in a config file the tools actually read, so that the approved document and the real behavior cannot drift.
36. As a Tech Lead, I want allowlist entries to require a reason and an expiry date, so that exceptions do not live forever.
37. As a Tech Lead, I want every allowlist entry and every configuration change listed in the summary, so that nobody hides findings silently.
38. As a Tech Lead, I want expired allowlist entries to stop working automatically, so that stale exceptions re-surface findings.
39. As a Tech Lead, I want exit codes that distinguish "blocking findings" from "tool error", so that delivery automation reacts correctly.
40. As a Tech Lead, I want the tool versions pinned and recorded in each report, so that results are reproducible.

### SonarQube administrator
41. As a SonarQube administrator, I want a documented one-time server setup (Docker, HTTPS, pinned version), so that I can host one central instance.
42. As a SonarQube administrator, I want a documented custom Quality Gate on overall code, so that old problems are not hidden by new-code-only rules.
43. As a SonarQube administrator, I want documented token permissions (Execute Analysis, optionally Create Projects), so that developers get least privilege.
44. As a SonarQube administrator, I want a diagnostic checklist for 401 and 403 errors, so that authorization problems are solved quickly.

### New developer
45. As a new developer, I want a one-page guide, so that I can install and run my first scan without help.
46. As a new developer, I want one-time install commands for Windows and macOS, so that setup takes minutes.
47. As a new developer, I want a self-test command, so that I can confirm my machine works before scanning real code.
48. As a new developer, I want a demo project with known planted issues, so that I can see what findings and fixes look like.

### Dashboard (Milestone 2)
49. As a developer, I want to start the dashboard with one command and have my browser open, so that I do not configure a server.
50. As a developer, I want a Run button with a project folder picker, so that I do not need the terminal.
51. As a developer, I want live per-tool progress and a cancel button, so that I stay in control of a long scan.
52. As a developer, I want a setup check screen showing each tool, version, and install command, so that I can fix prerequisites visually.
53. As a developer, I want a Sonar connection test, so that I find URL and token problems before scanning.
54. As a developer, I want to enter my Sonar token once into the OS secure store, so that I never handle it again.
55. As a developer, I want a results screen with overall status, per-tool status, severity mix, Quality Gate, and Sonar link, so that I see the whole picture at a glance.
56. As a developer, I want a "must fix" card list ordered by importance, so that I fix the right things first.
57. As a developer, I want a findings table with filters by tool, severity, and file, so that I can work through issues.
58. As a developer, I want secret findings to show file and line but never the value, so that the screen is safe to share.
59. As a developer, I want scan history per project, so that I can see progress over time.
60. As a developer, I want a before-and-after comparison of two scans, so that I can show remediation worked.
61. As a developer, I want a trend chart of findings over recent scans with the blocking threshold marked, so that I see direction at a glance.
62. As a developer, I want export buttons for HTML, Markdown, and JSON, so that I can attach a report to a delivery.
63. As a developer, I want a settings screen for Sonar URL, token, exclusions, and allowlist, so that I configure everything in one place.
64. As a Tech Lead, I want thresholds shown read-only in the dashboard, so that developers cannot weaken policy locally.
65. As a developer, I want a notification for allowlist entries about to expire, so that I renew or fix them in time.
66. As a developer, I want dark and light themes, so that the app suits my environment.
67. As a developer, I want the dashboard to look and feel like the supplied glass reference, so that it is pleasant to use daily.
68. As a developer with reduced-transparency or reduced-motion settings, I want the interface to adapt, so that it stays readable and comfortable.

---

## Implementation Decisions

### 1. Architecture

- **Engine plus thin wrappers.** One Python engine (Python 3.9 or newer) holds all logic: prerequisite checks, tool orchestration, normalization, threshold evaluation, redaction, report writing, exit code. The Windows and macOS wrappers only locate Python, forward arguments, and call the engine. Reason: two codebases drift; one engine cannot.
- **The dashboard (Milestone 2) is a client of the engine.** It starts the engine as a subprocess, reads its event stream and output files, and never calls tools directly.
- **Contracts between components are files and exit codes:** an event stream, `summary.json`, and exit codes. Anything that can read those can replace the dashboard later (a central web dashboard, a CI job).
- **No silent installation.** The engine detects missing tools and prints the exact install command for the current OS. It never installs anything by itself.

### 2. Command-line interface

Entry points requested by the business, kept exactly:

- Windows: `.\run-security-scan.ps1`
- macOS: `./run-security-scan.sh`

Both accept the same options (PowerShell uses `-Name` style, shell uses `--name` style, same meaning):

| Option | Meaning |
|---|---|
| project directory (positional, optional) | Directory to scan. Default: current directory. |
| `--no-fail` | Always exit 0 after writing reports. Status inside reports is unchanged. |
| `--build` | Allow the engine to build Java (Maven, Gradle) or .NET projects before analysis. |
| `--only <tools>` | Run only listed tools (comma-separated). For debugging. |
| `--skip <tools>` | Skip listed tools. The summary marks them SKIPPED and the overall status cannot be PASS. |
| `--timeout <minutes>` | Per-tool timeout override. Default defined in config. |
| `--config <file>` | Alternative project scan config. Default: `.scan-config.yml` in the project root if present. |
| `--self-test` / `-SelfTest` | Run the built-in self-test (section 14). |
| `--version` | Print engine version and pinned tool versions. |

Also provide a `secscan` console command exposing `scan`, `ui` (Milestone 2), and `self-test` subcommands that call the same engine. The two named wrappers remain the primary documented path.

### 3. Prerequisite check

Before any scan, check and report each item with status OK, WARN (older than tested), or MISSING:

- Python 3.9+ (the wrapper checks this first; if absent, exit code 3 with install guidance)
- Semgrep, Gitleaks, Trivy, SonarScanner CLI, and Java 17 only if the SonarScanner distribution in use does not bundle a runtime
- Git (optional; enables commit info and Gitleaks history mode)
- SonarQube URL configured and reachable; token present; token accepted by the server
- Network access for Trivy database and Semgrep rule download, with standard proxy environment variables honored

A missing individual tool marks that tool ERROR with reason "not installed" and the scan continues. Only when the scan cannot start at all (no Python, project directory not found, zero usable tools) does the engine exit with code 3.

Minimum tested versions live in a single `tools.lock` configuration. An older tool gives a WARN, not a failure. Newer tools are accepted with a note. The summary records the actual version of every tool used.

Install guidance (Windows: winget or official installers; macOS: Homebrew or official installers) is stored in configuration, not hard-coded in logic. Semgrep on native Windows is limited; the engine first tries a native install, then Docker, then WSL, and reports ERROR with clear reasoning if none works. Official download pages are listed in the one-page guide.

### 4. Tool execution rules

General:

- Run every tool independently. A failure, crash, timeout, or non-zero exit in one tool never prevents the others from running.
- Each tool run ends in exactly one result: PASS, FAIL, or ERROR (plus SKIPPED when explicitly skipped by the user).
  - PASS: tool completed, no blocking findings.
  - FAIL: tool completed, at least one blocking finding.
  - ERROR: tool could not complete or result could not be trusted (missing tool, connection failure, authentication failure, crash, timeout, unreadable output).
- Tool exit codes are not interpreted as verdicts by themselves. Many scanners exit non-zero when they find issues. The engine reads the tool's report to decide.
- Capture stdout and stderr per tool into a redacted log in the reports folder.
- Tools run sequentially by default in Milestone 1 (simpler logs, predictable memory). Parallel execution is a later optimization.

**Semgrep**
- Telemetry off. Because registry "auto" configuration requires telemetry, do not use it. Use explicitly named rule packs (default, security-audit, secrets-excluded as handled by Gitleaks, plus language packs chosen by detected languages), downloaded online, and allow a locally vendored rule folder to override or extend them.
- Output JSON. Map severities per section 7.
- Do not follow symlinks outside the project. Respect exclusions.

**Gitleaks**
- Always run with redaction enabled so the secret value is never written, not even to raw reports.
- If the project is a git repository, scan full history. Otherwise scan the current files only. Record which mode ran in the summary.
- Use the subcommand style matching the pinned Gitleaks version.
- Every finding is mapped to Critical (section 7).
- Findings remain reportable by rule, file, line, commit, and a short fingerprint, but never the matched text.

**Trivy**
- Filesystem scan for vulnerabilities in dependency manifests and lockfiles, plus misconfiguration scanning of Docker and infrastructure-as-code files.
- Trivy's own secret scanning is disabled to avoid duplicating Gitleaks and to avoid a second place secret values could appear.
- Respect exclusions but always keep manifest and lockfile types visible to Trivy (section 6).
- Record whether the vulnerability database was updated or stale; a stale or failed database update is ERROR unless a recent cached copy exists, in which case WARN.
- Capture "fix available" for each vulnerability; thresholds use it (section 8).

**SonarQube Community Build**
- Use the SonarScanner CLI for JavaScript, TypeScript, Python, PHP, Go, and generic projects.
- Java: use existing compiled output when found; otherwise run with a visible "reduced analysis" warning. With `--build`, build first with the detected Maven or Gradle.
- .NET: use the .NET scanner begin/build/end flow, only with `--build`; otherwise run the generic scanner with a "reduced analysis" warning.
- The token is supplied through the environment variable `SONAR_TOKEN`, never on the command line, and never written to any log or report.
- Server URL comes from configuration (`SONAR_HOST_URL` or the shared config). Project key is derived from the project folder name (sanitized), shared by everyone scanning the same project. Community Build has no branch or pull request analysis, so a rescan replaces the previous result. This is documented and accepted.
- **Quality Gate result is mandatory.** After the scanner finishes, read the analysis task id from the scanner's output, poll the server until the background task completes (with a timeout), then fetch the project's Quality Gate status from the server API. The tool's PASS or FAIL comes from the gate: gate OK is PASS, gate ERROR is FAIL, anything that prevents getting a gate verdict is ERROR. Scanner success alone is never PASS.
- Fetch the project's issues and security hotspots from the server API for the findings list and severity counts.
- Provide the dashboard link: server URL plus project key.
- Distinguish error causes: unreachable server, TLS failure, 401 (bad or expired token), 403 (missing permission), 404 (project missing and cannot be created), task failed, timeout.
- Source code is sent to the central server. This is explicitly approved by the business for internal hosting.

### 5. Project detection and generic mode

- Detect languages and project types from manifests and file extensions (Java via Maven or Gradle files, .NET via solution or project files, JavaScript and TypeScript via package manifests, Python via requirements or pyproject, PHP via composer, Go via module files, Docker and infrastructure-as-code files).
- All four tools always run on any directory. Detection only tunes rule packs, Sonar settings, and warnings.
- Unknown stack: generic mode. Summary lists "reduced coverage" notes per tool.
- Monorepos: scan the whole directory as one project in Phase 1.

### 6. Exclusions

- A shared default exclusion list covers dependency folders (for example node_modules, vendor, virtual environments), build output (bin, obj, target, build, dist), version control internals, caches, IDE folders, minified and bundled files, source maps, and large binary or media files. The list lives in configuration.
- Trivy exception: manifests and lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml, pom.xml, gradle lockfiles, go.sum, go.mod, requirements files, poetry.lock, composer.lock, packages.lock.json, Dockerfiles, and similar) stay visible even inside otherwise excluded areas.
- Optional per-project `.scan-config.yml` adds exclusions and allowlist entries. Every entry in it appears in the summary under "configuration changes", so reviewers see what was hidden.
- Exclusions apply identically to each tool where the tool supports it; unsupported cases are listed in the summary.
- Respect `.gitignore` for file selection where the tool supports it, but dependency and build exclusions apply regardless.

### 7. Unified severity and normalization

Levels: Critical, High, Medium, Low, Info. Mapping lives in configuration and is printed in the thresholds document.

| Source | Source value | Unified |
|---|---|---|
| SonarQube | Blocker | Critical |
| SonarQube | Critical | High |
| SonarQube | Major | Medium |
| SonarQube | Minor | Low |
| SonarQube | Info | Info |
| Semgrep | ERROR | High |
| Semgrep | WARNING | Medium |
| Semgrep | INFO | Low |
| Trivy | CRITICAL | Critical |
| Trivy | HIGH | High |
| Trivy | MEDIUM | Medium |
| Trivy | LOW | Low |
| Trivy | UNKNOWN | Info |
| Gitleaks | any finding | Critical |

Normalized finding fields: stable id, tool, rule id, rule title, unified severity, original severity, category (secret, vulnerability, code issue, misconfiguration, hotspot), file path relative to project root, line, short description, fix guidance or fix version when available, reference link, allowlisted flag, blocking flag.

Sonar issues and hotspots are typed (bug, vulnerability, code smell, hotspot). Only security-relevant types plus Quality Gate drive blocking; others are reported.

### 8. Proposed thresholds (subject to Tech Lead approval)

Delivered as a human-readable `THRESHOLDS.md` and a machine-read `THRESHOLDS.yml` generated from or checked against each other; a test fails if they differ.

| Tool | Blocks delivery (FAIL) | Reported as warning only |
|---|---|---|
| Gitleaks | Any finding not allowlisted | none |
| Trivy vulnerabilities | Any Critical; any High with a fix available | High with no fix; Medium; Low |
| Trivy misconfiguration | Critical or High | Medium; Low |
| Semgrep | High (rule severity ERROR) | Medium; Low |
| SonarQube | Quality Gate status ERROR | Everything else, listed in the report |
| Any tool | ERROR is not a finding but makes the scan incomplete (exit code 2) | n/a |

Sonar Quality Gate (custom, on overall code, created once by the administrator): zero vulnerabilities; security rating A; all security hotspots reviewed; reliability rating A. No coverage condition in Phase 1.

Allowlist: entries require tool, rule or fingerprint, file pattern, reason, approver, and expiry date. Expired entries are ignored and flagged. Gitleaks allowlisting also needs the fingerprint, never the value.

### 9. Overall status and exit codes

Overall status values: PASS, FAIL, INCOMPLETE.

- PASS: all four tools PASS, none skipped.
- FAIL: at least one blocking finding, from any tool that completed.
- INCOMPLETE: no blocking findings found, but at least one tool ERROR or SKIPPED.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Overall PASS (or `--no-fail`) |
| 1 | At least one blocking finding (takes precedence over 2) |
| 2 | No blocking finding but at least one tool ERROR or SKIPPED (incomplete) |
| 3 | Scan could not start (Python missing, bad project directory, no usable tool) |

An incomplete scan is never reported as a pass.

### 10. Reports and redaction

Output folder: `scan-reports/` in the scanned project root. Contents:

- `summary.html` (human, self-contained, no external resources), `summary.md`, `summary.json`
- one redacted raw report per tool (JSON where possible)
- one redacted log per tool
- `events.jsonl` (progress event stream, section 12)

`summary.json` carries a schema version and contains: project name, path (relative or hashed per config), scan id, start and end time, duration, engine version, tool versions, git commit and branch when available (otherwise "not a git repository" plus a content timestamp), developer identifier (OS user, configurable), per-tool status and reason, per-tool counts by unified severity, Quality Gate verdict and failing conditions, SonarQube dashboard URL, overall status, exit code, blocking findings, all findings (normalized), allowlist entries used and expired, configuration changes, reduced-coverage notes, thresholds version.

`summary.html` and `summary.md` contain: header (project, date, commit or version), overall status banner, per-tool status table, severity counts, "Issues requiring fixes" list, Quality Gate section with dashboard link, configuration changes and exceptions, coverage notes.

Redaction rules (enforced in code at the report-writing boundary, not scattered):
- Secret values never reach any file. Gitleaks runs redacted; the engine additionally strips any match text field.
- The Sonar token, other tokens, and URL-embedded credentials are removed from logs and reports.
- The engine adds `scan-reports/` to the project's `.gitignore` when the project is a git repository and the entry is absent, and tells the developer.
- A redaction guard scans all report files for known secret patterns and for the real planted demo secret; any hit makes the engine delete the offending file's content and mark ERROR "redaction failure".

### 11. Secrets and token handling

- Sonar token: environment variable `SONAR_TOKEN` in Milestone 1; OS secure store (Windows Credential Manager, macOS Keychain) in Milestone 2, with the environment variable as an override.
- One-page guide documents setting the variable persistently and securely per OS, and warns against pasting tokens into scripts, tickets, or chat.
- Per-developer user tokens with Execute Analysis (and Create Projects only where needed).
- Token never echoed, never in process arguments, never in logs.

### 12. Event stream

The engine appends one JSON object per line to `events.jsonl` during a scan. Event types: scan_started, prerequisite_result, tool_started, tool_progress (optional), tool_finished (status, reason, counts), gate_result, report_written, scan_finished (overall status, exit code). Every event has a timestamp, scan id, and event type; no event ever carries a secret value. The terminal progress lines and the dashboard both derive from this one stream.

### 13. SonarQube central server (administrator task, documented, not built into the scanner)

- One central instance on an internal VM, Docker deployment, HTTPS through a reverse proxy, reachable over the company network or VPN, pinned Community Build version, persistent volumes, database as supported for production (not the embedded one), backups documented.
- Admin creates the custom Quality Gate and sets it as default, creates a developer group with the needed permissions, and issues or guides issuing user tokens.
- **Task 0 (conditional): diagnose authorization.** Run only if the first Sonar call returns 401 or 403. Checklist: confirm token type (user token versus project or global analysis token), confirm the token is being passed (environment variable present in the shell that runs the scan), confirm the server URL matches exactly (scheme, host, port, path), test authentication with a direct call to the server's authentication validation endpoint, check Execute Analysis and Create Projects permissions for the user, check whether a proxy or reverse proxy strips the authorization header, and confirm the project key is not owned by another project with restricted permissions. Record the confirmed root cause in the decisions log.

### 14. Self-test

`--self-test` runs on the current OS and requires no project from the user:

1. Check prerequisites and versions.
2. Scan the bundled demo project and compare against its expected-findings file.
3. Break each tool on purpose in turn (bad Sonar URL, bad token, tool hidden from the path) and confirm the others still run and the broken one reports ERROR with the right reason.
4. Confirm redaction: the planted fake secret appears nowhere under the reports folder.
5. Confirm exit codes for PASS-like, FAIL, and INCOMPLETE situations, and that `--no-fail` returns 0.
6. Confirm the Sonar Quality Gate verdict is read from the server when a server is configured; otherwise mark that check SKIPPED with a reason.
7. Print one checklist of PASS or FAIL lines and exit non-zero if any fail.

This is how Windows and macOS correctness is proven: the owner runs the self-test once on each OS. The agent must not claim a platform works unless the self-test (or equivalent automated run) executed on that platform.

### 15. Demo repository

A small project owned by the team with intentionally planted issues in Python, JavaScript, and Java: one fake secret (obviously fake, never a real credential), one dependency with a known vulnerability, one insecure code pattern Semgrep catches, one Dockerfile misconfiguration, and one bug Sonar reports. An expected-findings file lists exactly what a correct scan must find. A second state of the repo (the "fixed" state) removes every planted issue so the remediate-and-rescan demo shows status moving from FAIL to PASS. A short scripted demo covers install, run, findings, remediation, rescan.

Additional test projects supplied by the owner (open-source, sanitized, or customer-like) are placed in a separate test folder. They have no expected-findings file; tests on them check behavior (all tools ran, reports exist, redaction holds, exit code consistent), not exact counts. Real customer code or real secrets must never be committed to the repository or sent to the agent.

### 16. Milestone 2: local dashboard

**Runtime**
- Local web application. Backend: Python (FastAPI) in the same environment as the engine. Frontend: React. Started by the `ui` command, which opens the default browser.
- Binds to `127.0.0.1` only, random free port, one-time session token placed in the opening URL and required on every request. Reject requests with foreign Origin or Host headers. Single user per machine, no login screen.
- Starts scans as engine subprocesses; reads `events.jsonl` for live progress; cancel stops the whole process tree and marks the scan CANCELLED.
- History in a local SQLite database in the per-user application data folder. Stores paths, project names, statuses, counts, timestamps, and report locations. Never stores secret values or tokens. Keeps the last 50 scans per project, configurable. Reports themselves stay in each project's reports folder.
- Thresholds read-only. Developers may add allowlist entries (reason and expiry required) through settings, stored in the project's `.scan-config.yml`.
- English only, all UI text in string files so another language can be added later.
- Installation: Python package installed with `pipx` from the private repository, or a release zip with a bootstrap script. No signed executables in this phase.

**Screens** (seven, same visual language)

1. **Home**: project list with last status, last scan time, Run button; trend chart; tool donut; severity mix bar.
2. **Setup check**: each tool with version, status, install command; Sonar connection test; token status (set or not set, never shown).
3. **Scan run**: per-tool progress cards driven by the event stream; log tail (redacted); cancel.
4. **Results**: header with project, date, commit; overall status; per-tool PASS/FAIL/ERROR; severity counts; Quality Gate verdict and Sonar link; "must fix" cards; export buttons for HTML, Markdown, JSON.
5. **Findings**: filterable table (tool, severity, category, file, text search), detail drawer with fix guidance; secrets show file and line only.
6. **History**: scans per project; select two scans to compare (new, fixed, unchanged findings); trend chart.
7. **Settings**: Sonar URL, token entry, exclusions, allowlist with expiry warnings, read-only thresholds and severity mapping, theme toggle.

**Visual design: glass reference**

The supplied screenshot is stored with the spec as the design reference and is the visual target. Fidelity level: layout-faithful (same structure, arrangement, and look; exact values chosen by the agent and expressed as design tokens).

Elements to reproduce:
- Dark gradient background with warm and cool tones, created with CSS only (no image files).
- Frosted translucent cards, large rounded corners, thin light borders, soft shadows.
- Top pill navigation holding the seven screens; left vertical icon rail (search, new scan, starred projects, reports, settings, theme toggle); round avatar for the developer; bell for allowlist expiry notices.
- Page header with large title and three inline KPIs (overall status, blocking issue count, Quality Gate).
- Large area chart card with a dashed horizontal blocking-threshold line and a range toggle (last 7 or 30 scans).
- Small cards: donut gauge (tools passed out of four) and a segmented stacked bar (severity mix).
- A grid of "must fix" cards: small caption (tool), title (rule), subtitle (file and line), large count, small badges.
- Accent palette: lime green for success, coral for failure and warnings, muted blue for informational, neutral grey for disabled. Mapping from the reference's sales metrics to security metrics is listed above and is binding.
- Design tokens (colors, blur radius, surface opacity, border color, radius scale, spacing scale, type scale, shadows) live in one tokens file consumed by both themes. Dark is default; light is supported and lower priority.
- One open-licence rounded geometric sans font bundled locally (for example Outfit or Urbanist), no remote font or analytics calls, so the UI looks the same offline.

Accessibility and robustness:
- Body text contrast at least 4.5 to 1 against the effective glass surface in both themes.
- Severity and status are always shown as text label plus icon plus color, never color alone.
- When backdrop blur is unsupported or the OS asks to reduce transparency, cards become solid surfaces with the same layout.
- Respect reduced-motion settings; no essential information conveyed by animation.
- Keyboard navigable; visible focus ring; screen-reader labels on charts (a text summary of each chart).

Screens 2 to 7 reuse the same components and tokens; no extra reference was supplied. The agent proposes layouts and the Tech Lead reviews screenshots before the Milestone 2 merge.

**Later (not in either milestone)**: central multi-developer dashboard, CI integration, parallel tool execution, offline mode, Arabic UI, signed installers, desktop shell.

### 17. Deliverables

Milestone 1:
- Working Windows and macOS wrappers plus engine, configuration examples (`tools.lock`, thresholds, exclusions, `.scan-config.yml` example, severity mapping)
- `THRESHOLDS.md` for Tech Lead approval
- Downloadable package or repository with installation instructions
- **One-page developer guide** (exactly one page; see below)
- Sample scan reports (HTML, Markdown, JSON) from the demo repository in both "findings" and "fixed" states, redacted
- Demo script (short walkthrough of install, run, findings, remediation, rescan)
- Administrator guide for SonarQube server and Quality Gate (separate from the one-pager)
- Decisions log

Milestone 2:
- Dashboard application, screen screenshots for Tech Lead review, dashboard section appended to the guide only as a short pointer (the one-page limit applies to the developer guide)

**One-page guide outline** (strictly one page): prerequisites for Windows and macOS; official download links for Python, Git, Semgrep, Gitleaks, Trivy, SonarScanner; one-time install and environment commands per OS; SonarQube URL and secure token setup; how to get the package and run the script; where to find and read results; three-line troubleshooting for the most common failures (token, URL, missing tool).

---

## Testing Decisions

**What makes a good test here:** test external behavior only: exit codes, statuses, files produced, content of reports, absence of secrets. Do not test internal function structure. Prefer recorded real tool outputs (fixtures) over mocks of internals.

**Seams (checkpoint with the owner; proposed highest-level seams):**

1. **Engine boundary**: given a project directory and configuration, produce the reports folder and an exit code. Nearly every behavior is tested here with fixture tool outputs and, for integration, real tools.
2. **Dashboard HTTP boundary (Milestone 2)**: the local API the UI calls (start scan, stream progress, read results, history), tested with a fake engine that replays events.
3. **Browser boundary (Milestone 2)**: end-to-end UI tests (Playwright) against the real dashboard and a replayed scan.

Everything below uses these three seams. Do not add new seams without writing the reason in the decisions log.

**Test labels** (every test carries exactly one):
- `automated`: runs anywhere without humans or network.
- `automated-online`: needs internet and installed tools; runs on the agent's machine if available.
- `needs-sonar`: needs the live SonarQube test server and a token; otherwise replayed against recorded API responses and marked "replayed".
- `self-test-Windows`, `self-test-macOS`: proven by the owner running the self-test on that OS.

**Behavior tests (engine)**
1. Runs from project root and with a directory argument; both produce identical reports.
2. Each tool broken on purpose (not installed, bad Sonar URL, bad token, forced timeout, crash) yields ERROR with correct reason while all other tools still produce results.
3. Tool exit codes do not decide verdicts; report content does (a tool that exits non-zero with findings is FAIL, a tool that exits zero with unreadable output is ERROR).
4. Sonar verdict comes from the Quality Gate: a run where the scanner succeeds but the gate fails is FAIL; a run where the gate cannot be fetched is ERROR.
5. Reports exist and are valid: three summaries plus per-tool raw files plus events; `summary.json` validates against its schema.
6. Summary contains project name, date, commit or version, per-tool status, severity counts, fix list, overall status, Sonar link.
7. Redaction: the planted demo secret and a set of synthetic token patterns appear in no file under the reports folder, in logs, or in events.
8. Exit codes 0, 1, 2, 3 and `--no-fail` behave as specified, including precedence of 1 over 2.
9. Exclusions: dependency, build, and generated folders produce no findings; lockfiles still reach Trivy; configuration changes appear in the summary.
10. Allowlist: valid entry suppresses; expired entry stops suppressing and is flagged; entry missing reason or expiry is rejected.
11. Thresholds: changing the thresholds file changes blocking results; the markdown and the yaml thresholds cannot disagree.
12. Unknown project type: generic mode runs, reduced coverage listed.
13. Java and .NET without build: warning shown; with `--build` (where toolchain present): deeper analysis runs.
14. Git versus non-git project: history mode versus file mode recorded correctly; reports folder added to `.gitignore` only in git projects.
15. Unified severity mapping matches the table for every source value.
16. Demo repo findings state matches the expected-findings file exactly; fixed state yields PASS; rescan shows improvement.
17. Test projects supplied by the owner: behavior-only checks (tools ran or ERROR with reason, reports exist, redaction holds, exit code consistent with summary).
18. Self-test passes on Windows and on macOS (run by the owner; results pasted back as proof).
19. Semgrep never runs with registry auto configuration and telemetry is off (inspect the actual command line in the log).

**Behavior tests (dashboard, Milestone 2)**
20. The server only listens on loopback; requests without the session token or with a foreign Origin are rejected.
21. Starting a scan from the UI produces the same reports as the command line; progress cards follow events; cancel stops all child processes and records CANCELLED.
22. Findings screen never displays secret values; secret rows show file and line only.
23. Token entry stores to the OS secure store and is never shown again or written to the database or logs.
24. History keeps the configured number of scans; compare shows new, fixed, and unchanged correctly.
25. Visual and accessibility checks: contrast measured on both themes; solid fallback when blur is disabled; reduced-motion honored; status never color-only; keyboard navigation works on every screen; screenshots of all seven screens for Tech Lead review.
26. Thresholds are read-only in the UI; allowlist changes require reason and expiry.

**Prior art:** none in this repository (new build). Follow the conventions of whatever test frameworks the agent picks, document them in the decisions log, and keep fixture tool outputs under version control with the tool version that produced each.

**Evidence rule:** every milestone ends with a test report listing each test, its label, result, and for `needs-sonar` or `self-test-*` tests whether it ran live, replayed, or is awaiting the owner.

---

## Out of Scope

- Central multi-user dashboard, authentication, roles, and cross-developer reporting
- Continuous integration and automatic scans on commit or pull request (Phase 1 is manual)
- Paid SonarQube editions, branch and pull request analysis, C and C++ analysis
- Automatic installation of tools, automatic fixing of findings
- Offline or air-gapped operation
- Signed installers, desktop shell, auto-update
- Languages other than English in the UI, reports, and guide
- Scanning container images, running containers, or live websites
- Sending reports to customers or external systems
- Real customer code or real credentials in the repository, tests, or demo

---

## Further Notes

- **Legal and data handling:** the business confirmed code may go to the internal SonarQube server. Semgrep telemetry stays off. Real customer code is never sent to the agent or committed.
- **Windows and Semgrep:** native Windows support for Semgrep is limited; the fallback chain (native, Docker, WSL) and its ERROR reporting are part of the contract. Record the real behavior observed during self-test in the decisions log.
- **Open fact, handled by Task 0:** the earlier SonarQube authorization failure has no known root cause yet. The owner reports no current error. Do not guess; diagnose only when a 401 or 403 appears.
- **Open dependency:** whether the build agent can reach the test SonarQube server is unknown. If not, mark `needs-sonar` tests as replayed and list them as awaiting live confirmation; never as passed live.
- **Thresholds need sign-off:** section 8 is a proposal. Do not mark Milestone 1 complete until the Tech Lead approves or amends `THRESHOLDS.md`.
- **Versions:** record tested versions of every tool, Python, and dashboard libraries in `tools.lock` and in every report. Prefer pinned, widely used versions at least two weeks old.
- **Product name:** `secscan` is a placeholder. The two wrapper names are fixed by the business.
- **Reference image:** `docs/ui-reference/01-overview-reference.png` ships beside this spec. It shows one screen (sales overview). Its mapping to security metrics is in section 16 and is binding for layout; its sales data is not.
