# Milestone 1 verification

November 14, 2026 · macOS 26.6.2 arm64. The shell wrapper ran on macOS with Python 3.14.0. Live scanner versions were Semgrep 1.146.0, Gitleaks 8.24.2, Trivy 0.76.1, and SonarScanner CLI 7.2.0.5079 (version and bundled JVM checks). Git 2.50.1 and PyYAML 6.0.3 were used. Automated fixtures cover the SonarQube API using a loopback server and synthetic responses.

| Spec test | Label | Result |
| --- | --- | --- |
| 1 · Current directory vs. explicit directory | automated | PASS · Same findings, counts, gate, and verdict |
| 2 · Missing tools, crash, timeout | automated | PASS · Other tools continue |
| 2 · Sonar 401, 403, unreachable URL | needs-sonar | PASS · Replayed; live confirmation pending |
| 3 · Exit code vs. report content | automated | PASS · Findings on nonzero exit; malformed report on zero exit |
| 4 · Quality Gate failure and unavailable gate | needs-sonar | PASS · Replayed with analysis id; live confirmation pending |
| 5 · Reports, JSON Schema and events | automated | PASS |
| 6 · Summary fields and Sonar link | automated | PASS |
| 7 · Fake secret and token redaction | automated | PASS · Reports, raw output, logs, events, terminal |
| 7 · Live Gitleaks history and redaction | automated-online | PASS |
| 8 · Exit codes 0–3 and informational mode | automated | PASS |
| 9 · Exclusions, lockfiles, database fallback | automated | PASS |
| 10 · Allowlist used, expired and invalid entries | automated | PASS |
| 11 · Runtime policy and Markdown sync | automated | PASS |
| 12 · Generic mode and reduced coverage | automated | PASS |
| 13 · Java/.NET without builds | automated | PASS · Reduced-coverage notes |
| 13 · Compiler-backed Java/.NET analysis | needs-sonar | Awaiting live server and build-toolchain verification |
| 14 · Git history mode, file mode and .gitignore | automated | PASS |
| 15 · Severity mapping | automated | PASS · All mapped values exercised through reports |
| 16 · Demo findings and fixed state | automated-online | PASS · Live Semgrep, Gitleaks and Trivy found all four expected non-Sonar issues; fixed state had zero findings |
| 16 · Fixed demo overall PASS and clean rescan | needs-sonar | PASS · Replayed and confirmed live on November 15 |
| 17 · Owner-supplied projects | automated-online | Awaiting sanitized test projects |
| 18 · macOS self-test | self-test-macOS | PASS · 22 checks, exit 0 against local SonarQube |
| 18 · Windows self-test | self-test-Windows | Awaiting the owner |
| 19 · Semgrep telemetry and named packs | automated-online | PASS · Live local rules and registry scans; metrics disabled |

The initial Trivy database fetch exceeded its time budget. Live scanner verification used a recent test cache populated from the official Trivy OCI layer after its SHA-256 digest was verified. The replay covers stale and unavailable cache behavior. The first macOS self-test caught a fixture check ID mismatch, which was corrected against Trivy's actual output.

## Live SonarQube follow-up

November 15, 2026 · Local SonarQube Community Build 26.10.0.133078 accepted the User Token and processed both demo states. The first live run revealed that the hotspot endpoint expects the query parameter `project`. The adapter and replay test now use that parameter. The rerun passed all 22 macOS self-test checks and all 11 automated tests passed. The live redacted samples show a findings scan with exit 1 and a fixed scan with exit 0 and zero findings. Both retrieved the default Quality Gate. A failing gate was exercised in replay. The custom overall-code gate, compiler-backed Java/.NET analysis, and the Windows self-test still need verification.

The proposed policy still needs owner approval. The owner authorized dashboard work after the live macOS self-test. The Windows self-test remains pending.

## Milestone 2 verification

| Spec test | Label | Result |
| --- | --- | --- |
| 20 · Loopback binding, session authentication and foreign requests | automated | PASS · Installed package served the bundle on a random loopback port. HTTP tests rejected missing credentials, replayed opening tokens and foreign Host or Origin. |
| 21 · Run, progress, and cancellation | automated | PASS · Replayed engine reached the UI, preserved reports, and cancelled a process with a child on macOS. The Windows process-tree test is pending. |
| 21 · Real engine smoke test | automated-online | PASS · The dashboard launched the actual engine and archived the fixed demo report. Semgrep, Gitleaks and Trivy passed. The dashboard launch shell had no Sonar token; live Sonar verification is recorded above. |
| 22 · Secret finding display | automated | PASS · The report API strips secret detail fields and the browser drawer shows the rule and location without a matched value. |
| 23 · Token routing and storage boundary | automated | PASS · The write-only API sent the token to the secure-store boundary and kept it out of API responses and SQLite. A live Keychain write and Windows Credential Manager still need hands-on verification. |
| 24 · History, comparison, export | automated | PASS · HTTP and browser tests covered retention, archived exports, and before/after comparison. |
| 25 · Browser accessibility and screenshots | automated | PASS · Axe reported no WCAG A/AA violations on the overview in dark and light themes. Browser checks covered keyboard dismissal, responsive layout, and the solid-surface fallback. Seven screenshots are available for review. |
| 26 · Read-only policy and validation | automated | PASS · The API exposes read-only thresholds and rejects invalid exceptions. |
| Windows dashboard and CLI | self-test-Windows | Awaiting team verification |
