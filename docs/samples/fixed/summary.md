# fixed

**PASS** · 2026-11-14T21:00:05.213+00:00 · not a git repository

Engine 0.1.0 · thresholds 1-proposed · exit 0

Quality Gate **OK**

[Open project in SonarQube](<http://127.0.0.1:9000/dashboard?id=fixed>)

## Tool results

| Tool | Status | Reason | Critical | High | Medium | Low | Info |
| --- | --- | --- | --- | --- | --- | --- | --- |
| semgrep | PASS |  | 0 | 0 | 0 | 0 | 0 |
| gitleaks | PASS |  | 0 | 0 | 0 | 0 | 0 |
| trivy | PASS |  | 0 | 0 | 0 | 0 | 0 |
| sonar | PASS |  | 0 | 0 | 0 | 0 | 0 |

## Severity counts

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

## Issues requiring fixes

None

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
