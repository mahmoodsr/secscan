# secscan developer guide

You need Python 3.9+, Semgrep, Gitleaks, Trivy and a SonarScanner CLI with a bundled runtime (or Java 17+). Git enables history scanning. Install the [versions in tools.lock](../secscan/data/tools.lock). Use the official download pages for [Python](https://www.python.org/downloads/), [Git](https://git-scm.com/downloads), [Semgrep](https://semgrep.dev/docs/getting-started/quickstart), [Gitleaks](https://github.com/gitleaks/gitleaks/releases), [Trivy](https://github.com/aquasecurity/trivy/releases), and [SonarScanner](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/scanners/sonarscanner).

**macOS** with Homebrew

```sh
brew install python git pipx gitleaks trivy sonar-scanner
pipx install semgrep==1.146.0 && pipx ensurepath
```

**Windows** with PowerShell and winget

```powershell
'Python.Python.3.13','Git.Git','Gitleaks.Gitleaks','AquaSecurity.Trivy' |
  ForEach-Object { winget install -e --id $_ }
py -3 -m pip install --user pipx
py -3 -m pipx install semgrep==1.146.0
py -3 -m pipx ensurepath
```

On Windows, extract the official SonarScanner ZIP with a bundled runtime and add its `bin` directory to your user PATH. Restart the terminal after changing PATH. The install commands may install newer versions. Use the pinned release artifacts to reproduce a handoff.

Ask the administrator for the HTTPS URL and a personal user token with Execute Analysis. Keep it in your approved OS or enterprise password store. Load it into the scan shell for each session. For persistent use on macOS, save a Keychain item named `secscan-sonar` using Keychain Access and run `export SONAR_TOKEN="$(security find-generic-password -s secscan-sonar -w)"`. On Windows, save it in Windows Credential Manager or an approved SecretManagement vault, then use `$env:SONAR_TOKEN = Get-Secret -Name secscan-sonar -AsPlainText` with your configured vault. Set the URL with `export SONAR_HOST_URL=https://sonar.example.internal` or `$env:SONAR_HOST_URL = 'https://sonar.example.internal'`. Keep tokens out of scripts, tickets, and chat.

Download and extract the private repository or release ZIP. From that directory run `python3 -m venv .venv; .venv/bin/python -m pip install .` on macOS, or `py -3 -m venv .venv; .\.venv\Scripts\python.exe -m pip install .` on Windows. Run `./run-security-scan.sh --self-test` or `.\run-security-scan.ps1 -SelfTest`. Scan a project with `./run-security-scan.sh /path/to/project` or `.\run-security-scan.ps1 C:\path\to\project`.

Open `scan-reports/summary.html` in the project. Check the overall verdict, the issues requiring fixes, and the Quality Gate. Fix findings and rerun. Use the Markdown or JSON summary for review or tooling.

- **Token rejected** · Confirm it is a personal token and ask the administrator to check Execute Analysis.
- **URL unreachable** · Check the exact HTTPS URL, company VPN, and certificate trust.
- **Tool missing** · Run the install command printed by secscan and open a fresh terminal.
