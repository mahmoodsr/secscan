# findings

**FAIL** · 2026-11-14T20:59:33.664+00:00 · not a git repository

Engine 0.1.0 · thresholds 1-proposed · exit 1

Quality Gate **OK**

[Open project in SonarQube](<http://127.0.0.1:9000/dashboard?id=findings>)

## Tool results

| Tool | Status | Reason | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- | --- | --- |
| semgrep | FAIL | blocking findings | 0 | 1 | 0 | 0 | 0 |
| gitleaks | FAIL | blocking findings | 1 | 0 | 0 | 0 | 0 |
| trivy | FAIL | blocking findings | 0 | 9 | 3 | 0 | 0 |
| sonar | PASS |  | 1 | 0 | 1 | 1 | 0 |

## Severity counts

| Severity | Count |
| --- | --- |
| Critical | 2 |
| High | 10 |
| Medium | 4 |
| Low | 1 |
| Info | 0 |

## Issues requiring fixes

| Tool | Severity | Rule | File and line | Fix |
| --- | --- | --- | --- | --- |
| gitleaks | Critical | github-pat | app.js:1 | Revoke or rotate the credential, then remove it from code and history. |
| semgrep | High | demo-python-eval | app.py:2 | Follow the remediation in the rule documentation. |
| trivy | High | DS-0002 | Dockerfile:3 | Add 'USER &lt;non root user name&gt;' line to the Dockerfile |
| trivy | High | CVE-2021-33503 | requirements.txt | Upgrade urllib3 to 1.26.5 |
| trivy | High | CVE-2023-43804 | requirements.txt | Upgrade urllib3 to 2.0.6, 1.26.17 |
| trivy | High | CVE-2025-66418 | requirements.txt | Upgrade urllib3 to 2.6.0 |
| trivy | High | CVE-2025-66471 | requirements.txt | Upgrade urllib3 to 2.6.0 |
| trivy | High | CVE-2026-21441 | requirements.txt | Upgrade urllib3 to 2.6.3 |
| trivy | High | CVE-2026-44431 | requirements.txt | Upgrade urllib3 to 2.7.0 |
| trivy | High | CVE-2026-97687 | requirements.txt | Upgrade urllib3 to 2.8.0 |
| trivy | High | CVE-2026-97689 | requirements.txt | Upgrade urllib3 to 2.8.0 |

## Quality Gate conditions

| Metric | Status | Actual | Threshold |
| --- | --- | --- | --- |
| new\_violations | OK | 0 | 0 |

## Coverage notes

    Symlinks are excluded from current-file scans.
    Reduced Java analysis: compiled classes are missing; run with --build for compiler-backed analysis.
    Reduced Java analysis: compiled classes are missing; Java files are excluded from SonarQube.

## Configuration changes

    {
      "semgrep_rules": "rules",
      "exclusions": [
        "rules",
        "scan.yml"
      ],
      "record_developer": false,
      "config_file": "scan.yml"
    }

## Exceptions used

    []

## Expired exceptions

    []

## Tool versions

    {
      "python": "3.14.0",
      "semgrep": "1.146.0",
      "gitleaks": "8.24.2",
      "trivy": "0.76.1",
      "sonar": "7.2.0.5079",
      "git": "2.50.1"
    }
