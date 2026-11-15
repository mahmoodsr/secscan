# Run the remediation demo

1. Install the four tools using the [developer guide](DEVELOPER_GUIDE.md) and set your SonarQube URL and token.
2. Run the walkthrough from the secscan checkout. It copies both states into a temporary directory and prints where to find the reports.

   ```sh
   .venv/bin/python docs/demo.py
   ```

   On Windows run `.\.venv\Scripts\python.exe docs\demo.py`.

3. Open the first state's `summary.html`. Find the Python dynamic evaluation, the fake GitHub token, the vulnerable Python dependency, the root Docker user, and the JavaScript bug. The [expected cases](../secscan/demo/expected.yml) name the planted findings. A newer Trivy database may report additional advisories.
4. Open the fixed state's summary. The fixes replace dynamic evaluation with JSON parsing, remove the credential and JavaScript bug, remove the vulnerable dependency, and set an unprivileged container user. All four tools must complete successfully for the rescan to PASS.

Running against a live SonarQube instance creates or updates the demo project keys `findings` and `fixed`. The built-in `--self-test` also checks failures, exit codes, and redaction.
