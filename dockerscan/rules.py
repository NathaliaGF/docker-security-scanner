from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    description: str
    detail: str
    fix: str


# ── docker-compose.yml checks ─────────────────────────────────────────────────

COMPOSE_RULES: dict[str, Rule] = {
    "DC001": Rule(
        id="DC001",
        severity="HIGH",
        description="Container running as root",
        detail=(
            "No `user:` directive was found, or it is explicitly set to root. "
            "Running as root inside a container maximises the blast radius of a container escape."
        ),
        fix="Add `user: 1000:1000` (or any non-root UID:GID) to the service definition.",
    ),
    "DC002": Rule(
        id="DC002",
        severity="HIGH",
        description="Privileged port exposed to host (< 1024)",
        detail=(
            "Ports below 1024 are privileged. Binding one on the host can conflict with "
            "system services and may require elevated privileges to reconfigure."
        ),
        fix="Use a non-privileged host port (>= 1024), e.g. `8080:80`.",
    ),
    "DC003": Rule(
        id="DC003",
        severity="MEDIUM",
        description="Image with `latest` tag (or no tag)",
        detail=(
            "Using `latest` makes builds non-reproducible: upstream updates can "
            "silently introduce breaking changes or new vulnerabilities."
        ),
        fix="Pin to a specific version, e.g. `postgres:16.2` or use an image digest.",
    ),
    "DC004": Rule(
        id="DC004",
        severity="HIGH",
        description="Sensitive path mounted as volume",
        detail=(
            "Mounting `/`, `/etc`, or `/var/run/docker.sock` grants the container "
            "privileged access to the host filesystem or the Docker daemon."
        ),
        fix=(
            "Remove the dangerous mount. If the Docker socket is required "
            "(e.g., CI agents), use a socket proxy like `tecnativa/docker-socket-proxy`."
        ),
    ),
    "DC005": Rule(
        id="DC005",
        severity="MEDIUM",
        description="Plaintext secret in environment variable",
        detail=(
            "Secrets in `environment:` are stored in plain text and exposed via "
            "`docker inspect`, process lists, container logs, and version-controlled compose files."
        ),
        fix=(
            "Use Docker secrets, a secrets manager (HashiCorp Vault, AWS Secrets Manager), "
            "or an `.env` file that is excluded from version control."
        ),
    ),
    "DC006": Rule(
        id="DC006",
        severity="LOW",
        description="`restart: always` without a health check",
        detail=(
            "Without a `healthcheck`, Docker cannot distinguish a running-but-broken container "
            "from a healthy one, so `restart: always` may loop on a broken service indefinitely."
        ),
        fix="Add a `healthcheck` block to the service definition.",
    ),
    "DC007": Rule(
        id="DC007",
        severity="HIGH",
        description="`privileged: true` enabled",
        detail=(
            "A privileged container has full access to the host kernel, all devices, "
            "and host namespaces — effectively root on the host machine."
        ),
        fix=(
            "Remove `privileged: true` and use `cap_add` with only the specific "
            "capabilities the service actually needs."
        ),
    ),
    "DC008": Rule(
        id="DC008",
        severity="MEDIUM",
        description="Host network mode (`network_mode: host`)",
        detail=(
            "Host networking removes all network isolation: the container shares the "
            "host's network stack and can bind to any host port."
        ),
        fix="Use the default bridge network or a custom named network instead.",
    ),
    "DC009": Rule(
        id="DC009",
        severity="LOW",
        description="No CPU or memory limits defined",
        detail=(
            "Without `mem_limit`/`cpus` (or `deploy.resources.limits`), a misbehaving "
            "container can exhaust all host resources, causing a denial-of-service."
        ),
        fix=(
            "Set `mem_limit` and `cpus` at the service level, or use "
            "`deploy.resources.limits.memory` and `deploy.resources.limits.cpus`."
        ),
    ),
    "DC010": Rule(
        id="DC010",
        severity="MEDIUM",
        description="Dangerous Linux capabilities added",
        detail=(
            "`cap_add: ALL` or high-risk capabilities such as `SYS_ADMIN` and `NET_ADMIN` "
            "grant near-root privileges and can be used to escape the container."
        ),
        fix=(
            "Use `cap_drop: ALL` first, then add back only the specific capabilities "
            "your service requires."
        ),
    ),
}


# ── Dockerfile checks ─────────────────────────────────────────────────────────

DOCKERFILE_RULES: dict[str, Rule] = {
    "DF001": Rule(
        id="DF001",
        severity="HIGH",
        description="Running as root (USER root or no USER instruction)",
        detail=(
            "Without a USER instruction the image runs as root by default. "
            "This maximises the impact of any container escape vulnerability."
        ),
        fix=(
            "Add a non-root user and switch to it before the final CMD/ENTRYPOINT: "
            "`RUN useradd -r appuser && USER appuser`."
        ),
    ),
    "DF002": Rule(
        id="DF002",
        severity="MEDIUM",
        description="Base image using `latest` tag (or no tag)",
        detail=(
            "Using `latest` makes image builds non-reproducible and can silently "
            "pull in vulnerable package versions or breaking changes."
        ),
        fix="Pin to a specific tag or digest, e.g. `python:3.12-slim`.",
    ),
    "DF003": Rule(
        id="DF003",
        severity="HIGH",
        description="Hardcoded credentials in ENV or ARG",
        detail=(
            "Secrets baked into ENV or ARG instructions are permanently stored in "
            "image layers and are visible via `docker history` and `docker inspect`."
        ),
        fix=(
            "Use BuildKit `--secret` mounts (`RUN --mount=type=secret …`) or "
            "inject secrets at runtime via a secrets manager."
        ),
    ),
    "DF004": Rule(
        id="DF004",
        severity="MEDIUM",
        description="`apt-get install` without `--no-install-recommends`",
        detail=(
            "Without `--no-install-recommends`, apt installs recommended packages "
            "that are usually unnecessary, increasing the image's attack surface and size."
        ),
        fix="Use `RUN apt-get install -y --no-install-recommends <package>`.",
    ),
    "DF005": Rule(
        id="DF005",
        severity="LOW",
        description="`COPY . .` without a .dockerignore file",
        detail=(
            "Copying the entire build context may inadvertently include `.env` files, "
            "credentials, local secrets, or large directories that inflate image size."
        ),
        fix=(
            "Create a `.dockerignore` file to exclude `.env`, `*.pem`, `.git`, "
            "test fixtures, and any other files not needed in the image."
        ),
    ),
    "DF006": Rule(
        id="DF006",
        severity="MEDIUM",
        description="Remote script piped directly into a shell (curl | bash)",
        detail=(
            "`curl | bash` (or `wget | sh`) executes a remote script without any "
            "integrity verification, enabling supply-chain attacks."
        ),
        fix=(
            "Download the script first, verify its checksum (sha256sum), then execute — "
            "or install the software through a signed package manager instead."
        ),
    ),
    "DF007": Rule(
        id="DF007",
        severity="LOW",
        description="More than 3 consecutive RUN instructions",
        detail=(
            "Each RUN creates a separate image layer. Multiple small layers slow builds, "
            "increase image size, and can leave temporary files in intermediate layers."
        ),
        fix=(
            "Chain related commands with `&&` into a single RUN, and clean up "
            "package caches in the same layer: `RUN apt-get install … && rm -rf /var/lib/apt/lists/*`."
        ),
    ),
    "DF008": Rule(
        id="DF008",
        severity="MEDIUM",
        description="Sensitive port exposed (SSH 22, Telnet 23, or RDP 3389)",
        detail=(
            "Exposing ports 22, 23, or 3389 signals that a remote access daemon "
            "(SSH, Telnet, RDP) is running inside the image, which is a security anti-pattern."
        ),
        fix=(
            "Remove the remote access daemon from the image. "
            "Use `docker exec` or a sidecar container for debugging access."
        ),
    ),
    "DF009": Rule(
        id="DF009",
        severity="HIGH",
        description="Private key or TLS certificate copied into image",
        detail=(
            "Copying `.pem`, `id_rsa`, `.key`, or similar files bakes credentials "
            "into every image layer permanently — including intermediate layers that survive `docker history`."
        ),
        fix=(
            "Use BuildKit `--mount=type=secret` to expose secrets at build time "
            "without persisting them in any layer, or inject them at runtime."
        ),
    ),
    "DF010": Rule(
        id="DF010",
        severity="LOW",
        description="End-of-life base image detected",
        detail=(
            "Images like `ubuntu:16.04` or `debian:8` are end-of-life and no longer "
            "receive security patches, meaning known CVEs will never be fixed."
        ),
        fix="Upgrade to a currently maintained base image (e.g. `ubuntu:24.04`, `debian:12`).",
    ),
}
