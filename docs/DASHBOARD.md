# Local dashboard

From your secscan checkout, launch `./run-security-scan.sh --ui` on macOS or `.\run-security-scan.ps1 -UI` on Windows after installing the package. The installed `secscan ui` entry point is also available. The browser opens using a single-use URL on 127.0.0.1. Refresh the open tab to keep using it. Restart the dashboard if the browser session has expired.

1. In **Settings**, enter the SonarQube URL and user token, then save. Use `http://127.0.0.1:9000` for the local test instance. The dashboard stores the token in macOS Keychain or Windows Credential Manager. `SONAR_TOKEN` and `SONAR_HOST_URL` from the launch shell are supported.
2. Open **Setup** and click **Test connection**.
3. Open **Scan run**, choose an existing folder with **Browse…** or enter its full path, then click **Start scan**. Enable the build option for compiler-backed Java or .NET analysis.
4. Review the scan in **Results** or **Findings**. Use **History** to compare two scans of the same project. Reports remain in the project's `scan-reports` directory. The dashboard archives its completed runs under `scan-reports/history` and retains the last 50 entries per project by default. Changing retention trims dashboard history. Archived reports remain in the project.
5. Load a project in **Settings** to manage exclusions and exceptions. The bell lists entries for the selected project that are expired or expire within 14 days. Delivery thresholds are read-only.

The frontend bundle ships with the Python package. To rebuild it from source, run `npm --prefix dashboard ci` followed by `npm --prefix dashboard run build`. To run the browser suite, install Chromium with `cd dashboard && npx playwright install chromium`, then run `npm test`. Set `SECSCAN_BROWSER_CHANNEL=chrome` to use your installed Chrome. Set `SECSCAN_SCREENSHOTS` to an absolute directory to write the review images. The browser tests use an isolated history database and replayed scanner output.

The macOS scanner self-test passed live. Phase 2 proceeded on that basis at the owner's request. The Windows wrapper, folder picker, credential backend and process-tree cancellation path are retained for team verification.
