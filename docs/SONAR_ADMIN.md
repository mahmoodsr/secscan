# Internal SonarQube Community Build

Use a dedicated internal Linux VM and an approved Docker runtime. Pin both images and use PostgreSQL with a dedicated login and database. Back up the database before upgrades. Set the Linux host requirements from the product documentation, including `vm.max_map_count`, file descriptors, and thread limits. Host sizing and TLS certificate trust must cover the company network or VPN.

The example uses SonarQube Community Build `26.10.0.133078-community` and PostgreSQL `16.10`. Confirm these pins against your approved image catalog and current security policy before deployment. Keep the DB password and local environment file in the VM's secret management setup.

```yaml
services:
  sonarqube:
    image: sonarqube:26.10.0.133078-community
    depends_on:
      db:
        condition: service_healthy
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://db:5432/sonar
      SONAR_JDBC_USERNAME: sonar
      SONAR_JDBC_PASSWORD: ${SONAR_DB_PASSWORD:?configure the database password}
    ports: ["127.0.0.1:9000:9000"]
    volumes:
      - sonar-data:/opt/sonarqube/data
      - sonar-extensions:/opt/sonarqube/extensions
      - sonar-logs:/opt/sonarqube/logs
  db:
    image: postgres:16.10
    environment:
      POSTGRES_DB: sonar
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: ${SONAR_DB_PASSWORD:?configure the database password}
    healthcheck:
      test: [CMD-SHELL, pg_isready -U sonar -d sonar]
      interval: 10s
      timeout: 5s
      retries: 10
    volumes:
      - sonar-db:/var/lib/postgresql/data
volumes:
  sonar-data:
  sonar-extensions:
  sonar-logs:
  sonar-db:
```

Put a company HTTPS reverse proxy in front of the loopback port. Preserve the original Host and Authorization headers, and set `X-Forwarded-Proto: https`. Set the public server base URL in SonarQube to the exact URL developers will use. Verify certificate trust from the client machines and the scanner JVM. Back up PostgreSQL with `pg_dump -Fc` using the dedicated account, retain the Compose configuration and supported extensions, and regularly test restoration to a separate VM.

In **Quality Gates**, create a gate with these conditions on **Overall Code**, then set it as the default. Apply it explicitly to any existing projects that use a different gate.

| Metric | Fail when |
| --- | --- |
| Vulnerabilities | Greater than 0 |
| Security Rating | Worse than A |
| Security Hotspots Reviewed | Below 100% |
| Reliability Rating | Worse than A |

Create a developer group and grant Execute Analysis for its projects. Allow Browse and access to issues and hotspots for the same projects. Grant Create Projects only to developers expected to register projects, or provision project keys centrally. Developers generate their own **User Token** under **My Account → Security**. Revoke tokens when users leave or credentials are exposed. The scanner derives the project key from the folder name. Coordinate a consistent folder name. Community Build keeps one server analysis per project key and a rescan updates it.

## Authorization diagnosis

Run this checklist only after the first Sonar API call returns 401 or 403.

1. Confirm it is a user token, and confirm the scan shell has set `SONAR_TOKEN` without printing its value.
2. Confirm scheme, host, port, and any context path are identical to the configured base URL.
3. Validate the token against `/api/authentication/validate`. This example reads the value directly from the environment inside Python.

   ```sh
   python -c 'import json, os, urllib.request as u; r=u.Request(os.environ["SONAR_HOST_URL"].rstrip("/")+"/api/authentication/validate",headers={"Authorization":"Bearer "+os.environ["SONAR_TOKEN"]}); print(json.load(u.urlopen(r,timeout=10))["valid"])'
   ```

4. Check Execute Analysis and Browse on the project, and Create Projects if the key is new.
5. Check that each proxy forwards Authorization and that a different restricted project does not own the same key.
6. Record the verified root cause in [DECISIONS.md](DECISIONS.md).

References include [installing from Docker](https://docs.sonarsource.com/sonarqube-community-build/server-installation/from-docker-image), [backing up and restoring](https://docs.sonarsource.com/sonarqube-community-build/server-update-and-maintenance/maintenance/backup-and-restore), and [Quality Gates](https://docs.sonarsource.com/sonarqube-community-build/quality-standards-administration/managing-quality-gates/introduction-to-quality-gates/).
