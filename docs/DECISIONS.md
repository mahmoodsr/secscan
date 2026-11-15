# Decisions

- Retain the working name `secscan` and use a setuptools package with one runtime dependency, PyYAML. The platform wrappers call the same Python entry point.
- Use sequential scanner adapters. Each run has a single deadline covering its scan, builds, database steps, and gate retrieval. Sonar responses are polled by Compute Engine task id and the gate is fetched by analysis id.
- Apply current-file exclusions before tool execution by copying regular files into a private temporary workspace. Trivy also receives manifests and lockfiles that match excluded paths. Git-based selection uses tracked and unignored files. Gitleaks examines all refs in an isolated bare mirror, with historical exclusions applied to the returned paths. Source code is copied locally during a run, and the temporary scanner workspaces are removed when their context exits.
- Disable inline pushes to scanner policy where supported. Semgrep runs with metrics and inline suppression disabled. Registry rules are fetched by the engine and secret rules are filtered before the scan. Named packs may evolve independently of the pinned engine. A local rules directory makes a reproducible demo possible.
- Keep the current scan at the project report root. Use a per-project writer lock and atomic individual report replacement. Sanitize source snippets, match fields, and known credential patterns at the output boundary. Report JSON includes the actual exit code and a separate policy exit code so informational runs can be identified.
- With an unavailable live server, verify the Compute Engine and Quality Gate contract through an HTTP replay. Full scanner and server compatibility still requires the live self-test. There is no confirmed Sonar authorization issue to diagnose.
- Java without compiled classes excludes Java source from Sonar analysis and reports reduced coverage. The .NET build path uses scanner environment properties and the CLI analysis path to transfer credentials without arguments. Live .NET analysis is awaiting validation.
- Exercise behavior through command invocations and saved outputs with `unittest`, the JSON Schema validator, and synthetic replay tools. Scanner stdout fixture shapes are versioned alongside the replay runner. Live checks use the versions and results recorded in the test report.
- Use the installed YAML policy as the sole source for the proposed thresholds document. Regenerate with `python -m secscan.policy_doc > THRESHOLDS.md` after approval or policy changes.

- The demo declares one required Trivy vulnerability and one required Dockerfile check. The first live run showed Trivy 0.76.1 reports the root-user check as `DS-0002`; the demo and replay expectations use that ID. All listed planted issues must appear. Additional advisories are expected while the database evolves.
- A first-time live Trivy database download exceeded the registry transfer deadline in this environment. For the local verification run, the official OCI layer was fetched, checked against the registry's SHA-256 digest, and installed in an isolated test cache. The scanner's normal network update and stale-cache selection are exercised separately by the replay suite.

## Dashboard

- Proceeded after the live macOS self-test passed at the owner's request. Preserve Windows support and leave Windows verification and policy sign-off open for the team.
- Bind the dashboard to a prebound random loopback port. Exchange the one-time opening URL credential for an HttpOnly, SameSite session cookie. Reject foreign Host and Origin headers and cross-site browser requests.
- Run the installed Python engine as a child process and have the engine reuse the dashboard's run UUID in its report and events. Poll redacted events and subprocess output for progress. Snapshot completed reports inside each project. SQLite indexes the last 50 runs per project by default.
- Use platform Keychain and Credential Manager backends only. The token is write-only over the local API and kept outside SQLite and project configuration. A shell token takes precedence.
- Use React, locally bundled Outfit, and CSS gradients based on the supplied reference. The trend uses the project’s run history and marks the zero-blocking-findings delivery limit.
