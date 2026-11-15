# secscan

secscan runs Semgrep, Gitleaks, Trivy, and SonarScanner over a project. It writes a delivery verdict and redacted results under `scan-reports/`.

## Install and run

Start with the [one-page developer guide](docs/DEVELOPER_GUIDE.pdf). Install the package dependencies in a virtual environment from this repository.

**macOS**

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
./run-security-scan.sh /path/to/project
./run-security-scan.sh --self-test
```

**Windows**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\run-security-scan.ps1 C:\path\to\project
.\run-security-scan.ps1 -SelfTest
```

The wrappers use the current directory when no project is supplied. Installation also exposes `secscan scan` and `secscan self-test`. Use `pipx install .` if you prefer an isolated console command. Tool discovery uses the calling process's PATH. The macOS wrapper also checks `.scan-tools/bin` in the checkout, if it exists. Set `SONAR_HOST_URL` and `SONAR_TOKEN` for your session. Configure project exclusions and exceptions by copying [.scan-config.example.yml](.scan-config.example.yml) to the project root as `.scan-config.yml`.

`--only` and `--skip` accept comma-separated tool identifiers (`semgrep,gitleaks,trivy,sonar`). The Windows equivalents are `-Only` and `-Skip`. `--timeout` and `-Timeout` accept fractional minutes. `--build` and `-Build` opt into executing a project's Maven, Gradle or .NET build. Run it only for a project whose build you intend to execute. `--no-fail` or `-NoFail` returns 0 after writing reports and preserves the verdict in the summary.

| Exit | Meaning |
| --- | --- |
| 0 | PASS or informational exit requested |
| 1 | Blocking finding or failed Quality Gate |
| 2 | Incomplete with no blocking result |
| 3 | Scan could not start or write reports |

The latest reports replace the previous run. If a scan is forcibly terminated and the next scan reports an active writer, verify the PID listed in `scan-reports/.active` and remove that file after the previous process has exited.

## Local SonarQube for a personal project

Start Docker Desktop, then run the pinned Community Build on loopback. This local test instance uses the embedded database.

```sh
docker run -d --name secscan-sonarqube \
  -p 127.0.0.1:9000:9000 \
  -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
  sonarqube:26.10.0.133078-community
```

If Docker Desktop uses a separate context, prefix the command with `docker --context desktop-linux` in place of `docker`. For subsequent sessions, use `docker start secscan-sonarqube` in the same context.

When [SonarQube](http://127.0.0.1:9000) is ready, sign in with `admin` / `admin` and set a new password. Open **My Account → Security**, generate a **User Token**, and keep it in your password store. In your macOS zsh session, enter it through a hidden prompt and run the self-test.

```zsh
export SONAR_HOST_URL=http://127.0.0.1:9000
read -rs 'SONAR_TOKEN?Paste your SonarQube token: '
echo
export SONAR_TOKEN
./run-security-scan.sh --self-test
```

Use the [administrator guide](docs/SONAR_ADMIN.md) to configure the project's overall-code Quality Gate.

## Local dashboard

Install or update the package in the same environment as the scanner, then start the dashboard.

| macOS | Windows PowerShell |
| --- | --- |
| `.venv/bin/python -m pip install .` | `.\.venv\Scripts\python.exe -m pip install .` |
| `./run-security-scan.sh --ui` | `.\run-security-scan.ps1 -UI` |

You can also run `secscan ui` after `pipx install .` if the scanner tools are on PATH. The dashboard opens in your default browser. Use **Settings** to enter the local SonarQube URL and save a user token to the OS secure store, then use **Scan run** to choose a folder. Tokens already exported in the terminal take precedence. See [dashboard usage and verification](docs/DASHBOARD.md) and the [screen review](docs/ui-review/README.md).

## Review and verify

- [One-page project and dashboard overview](output/pdf/secscan-overview.pdf)
- [Proposed delivery thresholds](THRESHOLDS.md), [runtime policy](secscan/data/THRESHOLDS.yml), [tool pins](secscan/data/tools.lock), and [report schema](secscan/data/summary.schema.json)
- [SonarQube administrator guide](docs/SONAR_ADMIN.md)
- [Demo walkthrough](docs/DEMO.md) and [sample reports](docs/samples)
- [Decisions](docs/DECISIONS.md) and [verification evidence](docs/TEST_REPORT.md)

Run deterministic tests with `python -m pip install '.[test]'` followed by `python -m unittest discover -s tests -v`. Run the wrapper's self-test on Windows and macOS with the pinned tools on PATH.
