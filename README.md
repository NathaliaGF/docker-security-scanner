# Docker Security Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Security Tool](https://img.shields.io/badge/Security-Tool-red?logo=shield&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?logoColor=white)
![Tests](https://img.shields.io/badge/Tests-105%20passing-brightgreen)

A lightweight CLI tool that statically analyses `docker-compose.yml` files and `Dockerfile`s for security misconfigurations, producing colour-coded terminal reports or machine-readable JSON output.

Docker Security Scanner implements 20 hand-crafted rules (10 per file type) that cover the most impactful container security mistakes: running as root, baking secrets into images, exposing privileged ports, mounting the Docker socket, using end-of-life base images, and more. It requires no Docker daemon, no internet access, and no heavy frameworks — just Python and two small dependencies.

---

## Installation

```bash
git clone https://github.com/your-username/docker-security-scanner.git
cd docker-security-scanner
pip install -r requirements.txt
```

Python 3.10 or higher is required.

---

## Usage

### Scan a single file

```bash
python main.py --file docker-compose.yml
python main.py --file path/to/Dockerfile
```

### Scan an entire project directory (recursive)

```bash
python main.py --dir ./my-project
```

### Filter by severity

```bash
# Show only HIGH-severity findings
python main.py --file docker-compose.yml --severity HIGH
```

### Export as JSON (for CI pipelines, dashboards, etc.)

```bash
python main.py --file docker-compose.yml --output json
python main.py --dir ./my-project --output json > report.json
```

### CI/CD integration

The scanner exits with code `1` when any **HIGH**-severity finding is present, and `0` otherwise. This lets you block pipelines on critical issues:

```yaml
# GitHub Actions example
- name: Docker Security Scan
  run: python main.py --dir . --severity HIGH
```

---

## Checks implemented

### docker-compose.yml

| ID     | Severity | Description                                               |
|--------|----------|-----------------------------------------------------------|
| DC001  | HIGH     | Container running as root (no `user:` or `user: root`)   |
| DC002  | HIGH     | Privileged host port exposed (< 1024)                     |
| DC003  | MEDIUM   | Image using `latest` tag or no tag                        |
| DC004  | HIGH     | Sensitive volume mounted (`/`, `/etc`, docker socket)     |
| DC005  | MEDIUM   | Plaintext secret in environment variable                  |
| DC006  | LOW      | `restart: always` without a health check                  |
| DC007  | HIGH     | `privileged: true` enabled                                |
| DC008  | MEDIUM   | Host network mode (`network_mode: host`)                  |
| DC009  | LOW      | No CPU or memory limits defined                           |
| DC010  | MEDIUM   | Dangerous Linux capabilities added (`SYS_ADMIN`, `ALL`…) |

### Dockerfile

| ID     | Severity | Description                                               |
|--------|----------|-----------------------------------------------------------|
| DF001  | HIGH     | `USER root` explicit or no `USER` instruction             |
| DF002  | MEDIUM   | Base image using `latest` tag or no tag                   |
| DF003  | HIGH     | Hardcoded credentials in `ENV` or `ARG`                   |
| DF004  | MEDIUM   | `apt-get install` without `--no-install-recommends`       |
| DF005  | LOW      | `COPY . .` without a `.dockerignore` file                 |
| DF006  | MEDIUM   | Remote script piped to shell (`curl \| bash`)              |
| DF007  | LOW      | More than 3 consecutive `RUN` instructions                |
| DF008  | MEDIUM   | Sensitive port exposed via `EXPOSE` (22, 23, 3389)        |
| DF009  | HIGH     | Private key or TLS certificate copied into image          |
| DF010  | LOW      | End-of-life base image (`ubuntu:16.04`, `debian:8`…)      |

---

## Security score

Every scan produces a score from **0 to 100**:

| Severity | Deduction per finding |
|----------|-----------------------|
| HIGH     | −15 points            |
| MEDIUM   | −7 points             |
| LOW      | −2 points             |

The score is calculated against the full finding list regardless of any `--severity` filter applied to the displayed output.

---

## Example output

```
╔══════════════════════════════════════════════════════════╗
║           DOCKER SECURITY SCANNER — RELATÓRIO            ║
╚══════════════════════════════════════════════════════════╝

📄 Arquivo: tests/samples/docker-compose.insecure.yml
──────────────────────────────────────────────────────────

🔴 [HIGH  ] DC007 — `privileged: true` enabled
            Serviço: api
            Linha:   19
            Detalhe: A privileged container has full access to the host kernel, all devices,
                     and host namespaces — effectively root on the host machine.
            Fix:     Remove `privileged: true` and use `cap_add` with only the specific
                     capabilities the service actually needs.

🟡 [MEDIUM] DC003 — Image with `latest` tag (or no tag)
            Serviço: db
            Linha:   26
            Detalhe: Using `latest` makes builds non-reproducible: upstream updates can
                     silently introduce breaking changes or new vulnerabilities.
            Fix:     Pin to a specific version, e.g. `postgres:16.2` or use an image digest.

🔵 [LOW   ] DC009 — No CPU or memory limits defined
            Serviço: api
            Linha:   8
            Detalhe: Without `mem_limit`/`cpus`, a misbehaving container can exhaust all
                     host resources, causing a denial-of-service.
            Fix:     Set `mem_limit` and `cpus` at the service level.

──────────────────────────────────────────────────────────
RESUMO: 14 achados  |  🔴 HIGH: 5  |  🟡 MEDIUM: 6  |  🔵 LOW: 3
Score de segurança: 0/100
──────────────────────────────────────────────────────────
```

### JSON output (`--output json`)

```json
{
  "file": "docker-compose.yml",
  "score": 62,
  "total_findings": 3,
  "findings": [
    {
      "id": "DC007",
      "severity": "HIGH",
      "description": "`privileged: true` enabled",
      "detail": "A privileged container has full access to the host kernel...",
      "fix": "Remove `privileged: true` and use `cap_add` with only the specific capabilities required.",
      "service": "api",
      "line": 12
    }
  ],
  "summary": {
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 1
  }
}
```

---

## Running the tests

```bash
pytest tests/ -v
```

The test suite contains **105 tests** — at least one positive and one negative test case per check, plus integration tests against the sample files in `tests/samples/`.

---

## Roadmap

- **Remote image scanning** — pull image metadata via the Docker API and scan layer history for baked secrets and vulnerable base images.
- **CI/CD integrations** — native GitHub Actions action and GitLab CI template; SARIF output format for GitHub Code Scanning.
- **Kubernetes manifest support** — extend checks to `Pod`, `Deployment`, and `DaemonSet` specs (equivalent rules for `securityContext`, `hostNetwork`, `privileged`, etc.).
- **Custom rule engine** — allow teams to define project-specific rules in YAML and load them at runtime.
- **SBOM integration** — cross-reference base image layers against CVE databases (Trivy, Grype) for vulnerability counts alongside config findings.

---

## License

MIT — see [LICENSE](LICENSE) for details.
