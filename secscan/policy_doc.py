"""Render the review copy directly from the runtime policy."""

from .config import load


def render():
    policy = load("THRESHOLDS.yml")
    blocking = policy["blocking"]
    fixed = blocking["trivy"]["vulnerability"]
    severity = load("severity.yml")

    def levels(values):
        return ", ".join(values)

    rows = [
        ("Gitleaks secrets", levels(blocking["gitleaks"]["secret"]) + " (all findings)"),
        ("Semgrep code issues", levels(blocking["semgrep"]["code issue"])),
        ("Trivy vulnerabilities", levels(fixed["severities"]) +
         f" ({levels(fixed['requires_fix'])} requires a fix)"),
        ("Trivy misconfigurations", levels(blocking["trivy"]["misconfiguration"])),
        ("SonarQube Quality Gate", blocking["sonar"]["gate"]),
    ]
    table = "\n".join(f"| {tool} | {rule} |" for tool, rule in rows)
    gate = policy["quality_gate"]
    mapping = "\n".join(f"| {tool} | {value} | {name} |"
                        for tool, values in severity.items() for value, name in values.items())
    return f"""# Delivery thresholds

Policy version `{policy['version']}`. Tech Lead approval pending. Machine policy lives in `secscan/data/THRESHOLDS.yml`.

| Tool or category | Blocks delivery |
| --- | --- |
{table}

Other findings are advisory. An ERROR or SKIPPED result makes an otherwise passing scan INCOMPLETE. A blocking result takes precedence over an incomplete result.

## SonarQube Quality Gate

Apply these conditions to overall code.

| Condition | Required result |
| --- | --- |
| Vulnerabilities | {gate['vulnerabilities']} |
| Security rating | {gate['security_rating']} |
| Security hotspots reviewed | {gate['security_hotspots_reviewed_percent']}% |
| Reliability rating | {gate['reliability_rating']} |

## Allowlist

Each entry requires a tool, rule or fingerprint, file pattern, reason, approver, and expiry date. Gitleaks requires a fingerprint. Expired entries have no effect and appear in the report. Allowlisting a Sonar finding leaves the server's Quality Gate verdict in force.

## Severity mapping

| Source | Source value | Unified severity |
| --- | --- | --- |
{mapping}
"""


if __name__ == "__main__":
    print(render(), end="")
