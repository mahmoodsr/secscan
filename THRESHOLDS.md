# Delivery thresholds

Policy version `1-proposed`. Tech Lead approval pending. Machine policy lives in `secscan/data/THRESHOLDS.yml`.

| Tool or category | Blocks delivery |
| --- | --- |
| Gitleaks secrets | Critical (all findings) |
| Semgrep code issues | High |
| Trivy vulnerabilities | Critical, High (High requires a fix) |
| Trivy misconfigurations | Critical, High |
| SonarQube Quality Gate | ERROR |

Other findings are advisory. An ERROR or SKIPPED result makes an otherwise passing scan INCOMPLETE. A blocking result takes precedence over an incomplete result.

## SonarQube Quality Gate

Apply these conditions to overall code.

| Condition | Required result |
| --- | --- |
| Vulnerabilities | 0 |
| Security rating | A |
| Security hotspots reviewed | 100% |
| Reliability rating | A |

## Allowlist

Each entry requires a tool, rule or fingerprint, file pattern, reason, approver, and expiry date. Gitleaks requires a fingerprint. Expired entries have no effect and appear in the report. Allowlisting a Sonar finding leaves the server's Quality Gate verdict in force.

## Severity mapping

| Source | Source value | Unified severity |
| --- | --- | --- |
| sonar | BLOCKER | Critical |
| sonar | CRITICAL | High |
| sonar | MAJOR | Medium |
| sonar | MINOR | Low |
| sonar | INFO | Info |
| semgrep | ERROR | High |
| semgrep | WARNING | Medium |
| semgrep | INFO | Low |
| trivy | CRITICAL | Critical |
| trivy | HIGH | High |
| trivy | MEDIUM | Medium |
| trivy | LOW | Low |
| trivy | UNKNOWN | Info |
| gitleaks | * | Critical |
