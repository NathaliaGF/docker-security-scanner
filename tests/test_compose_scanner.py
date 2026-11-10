"""
Unit tests for the docker-compose scanner — one test class per DC rule.
Each test writes a minimal compose snippet to a temp file, runs the scanner,
and asserts whether the expected finding is (or is not) produced.
"""

import pytest

from dockerscan import Finding
from dockerscan.compose_scanner import scan_compose

# ── Helpers ───────────────────────────────────────────────────────────────────

def _write(tmp_path, content: str) -> str:
    p = tmp_path / "docker-compose.yml"
    p.write_text(content, encoding="utf-8")
    return str(p)


def _has(findings: list[Finding], rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


def _get(findings: list[Finding], rule_id: str) -> Finding | None:
    return next((f for f in findings if f.rule_id == rule_id), None)


# ── DC001 — Root user ─────────────────────────────────────────────────────────

class TestDC001:
    def test_missing_user_triggers(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
        assert _has(scan_compose(_write(tmp_path, content)), "DC001")

    def test_explicit_root_triggers(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n    user: root\n"
        assert _has(scan_compose(_write(tmp_path, content)), "DC001")

    def test_uid_zero_triggers(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n    user: '0'\n"
        assert _has(scan_compose(_write(tmp_path, content)), "DC001")

    def test_non_root_user_passes(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n    user: '1000:1000'\n"
        assert not _has(scan_compose(_write(tmp_path, content)), "DC001")

    def test_finding_has_correct_severity(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
        f = _get(scan_compose(_write(tmp_path, content)), "DC001")
        assert f is not None and f.severity == "HIGH"


# ── DC002 — Privileged port ───────────────────────────────────────────────────

class TestDC002:
    def test_port_80_triggers(self, tmp_path):
        content = "version: '3'\nservices:\n  web:\n    image: nginx:1.25\n    ports:\n      - '80:80'\n"
        assert _has(scan_compose(_write(tmp_path, content)), "DC002")

    def test_port_443_triggers(self, tmp_path):
        content = "version: '3'\nservices:\n  web:\n    image: nginx:1.25\n    ports:\n      - '443:443'\n"
        assert _has(scan_compose(_write(tmp_path, content)), "DC002")

    def test_port_8080_passes(self, tmp_path):
        content = "version: '3'\nservices:\n  web:\n    image: nginx:1.25\n    ports:\n      - '8080:80'\n"
        assert not _has(scan_compose(_write(tmp_path, content)), "DC002")

    def test_finding_severity(self, tmp_path):
        content = "version: '3'\nservices:\n  web:\n    image: nginx:1.25\n    ports:\n      - '80:80'\n"
        f = _get(scan_compose(_write(tmp_path, content)), "DC002")
        assert f is not None and f.severity == "HIGH"


# ── DC003 — Latest tag ────────────────────────────────────────────────────────

class TestDC003:
    def test_latest_tag_triggers(self, tmp_path):
        content = "version: '3'\nservices:\n  db:\n    image: postgres:latest\n"
        assert _has(scan_compose(_write(tmp_path, content)), "DC003")

    def test_no_tag_triggers(self, tmp_path):
        content = "version: '3'\nservices:\n  db:\n    image: postgres\n"
        assert _has(scan_compose(_write(tmp_path, content)), "DC003")

    def test_pinned_tag_passes(self, tmp_path):
        content = "version: '3'\nservices:\n  db:\n    image: postgres:16.2\n"
        assert not _has(scan_compose(_write(tmp_path, content)), "DC003")

    def test_sha_digest_passes(self, tmp_path):
        content = "version: '3'\nservices:\n  db:\n    image: postgres@sha256:abcdef1234567890\n"
        assert not _has(scan_compose(_write(tmp_path, content)), "DC003")

    def test_finding_severity(self, tmp_path):
        content = "version: '3'\nservices:\n  db:\n    image: postgres:latest\n"
        f = _get(scan_compose(_write(tmp_path, content)), "DC003")
        assert f is not None and f.severity == "MEDIUM"


# ── DC004 — Sensitive volume ──────────────────────────────────────────────────

class TestDC004:
    def test_docker_sock_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  agent:\n    image: docker:24\n"
            "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC004")

    def test_root_mount_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    volumes:\n      - /:/host\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC004")

    def test_etc_mount_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    volumes:\n      - /etc:/etc-host\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC004")

    def test_named_volume_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    volumes:\n      - app_data:/app/data\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC004")

    def test_finding_severity(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        f = _get(scan_compose(_write(tmp_path, content)), "DC004")
        assert f is not None and f.severity == "HIGH"


# ── DC005 — Plaintext secret ──────────────────────────────────────────────────

class TestDC005:
    def test_secret_key_env_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    environment:\n      - SECRET_KEY=abc123\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC005")

    def test_password_env_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  db:\n    image: postgres:16\n"
            "    environment:\n      - POSTGRES_PASSWORD=hunter2\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC005")

    def test_api_key_env_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    environment:\n      - API_KEY=sk-prod-1234567890\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC005")

    def test_safe_env_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    environment:\n      - APP_PORT=8080\n      - LOG_LEVEL=info\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC005")

    @pytest.mark.parametrize("entry", [
        "POSTGRES_PASSWORD_FILE=/run/secrets/db_password",
        "GF_SECURITY_ADMIN_PASSWORD__FILE=/run/secrets/grafana_admin_password",
        "API_TOKEN=${API_TOKEN}",
        "API_TOKEN=$API_TOKEN",
        "DB_PASSWORD=${DB_PASSWORD:?set DB_PASSWORD}",
    ])
    def test_file_and_variable_references_are_not_plaintext(self, tmp_path, entry):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            f"    environment:\n      - {entry}\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC005")

    def test_mapping_syntax_file_variable_passes(self, tmp_path):
        content = (
            "services:\n  db:\n    image: postgres:16\n"
            "    environment:\n      POSTGRES_PASSWORD_FILE: /run/secrets/db_password\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC005")

    def test_reference_with_hardcoded_default_still_triggers(self, tmp_path):
        content = (
            "services:\n  db:\n    image: postgres:16\n"
            "    environment:\n      - DB_PASSWORD=${DB_PASSWORD:-hunter2}\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC005")

    def test_finding_severity(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    environment:\n      - SECRET_KEY=abc\n"
        )
        f = _get(scan_compose(_write(tmp_path, content)), "DC005")
        assert f is not None and f.severity == "MEDIUM"


# ── DC006 — restart:always without healthcheck ────────────────────────────────

class TestDC006:
    def test_restart_always_no_healthcheck_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    restart: always\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC006")

    def test_restart_always_with_healthcheck_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    restart: always\n"
            "    healthcheck:\n"
            "      test: [\"CMD\", \"curl\", \"-f\", \"http://localhost/health\"]\n"
            "      interval: 30s\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC006")

    def test_restart_unless_stopped_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    restart: unless-stopped\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC006")

    def test_finding_severity(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    restart: always\n"
        )
        f = _get(scan_compose(_write(tmp_path, content)), "DC006")
        assert f is not None and f.severity == "LOW"


# ── DC007 — privileged: true ──────────────────────────────────────────────────

class TestDC007:
    def test_privileged_true_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    privileged: true\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC007")

    def test_privileged_false_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    privileged: false\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC007")

    def test_missing_privileged_passes(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
        assert not _has(scan_compose(_write(tmp_path, content)), "DC007")

    def test_finding_has_service_name(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  myservice:\n    image: python:3.12\n"
            "    privileged: true\n"
        )
        f = _get(scan_compose(_write(tmp_path, content)), "DC007")
        assert f is not None and f.service == "myservice"

    def test_finding_severity(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    privileged: true\n"
        )
        f = _get(scan_compose(_write(tmp_path, content)), "DC007")
        assert f is not None and f.severity == "HIGH"


# ── DC008 — Host network ──────────────────────────────────────────────────────

class TestDC008:
    def test_host_network_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    network_mode: host\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC008")

    def test_bridge_network_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    network_mode: bridge\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC008")

    def test_no_network_mode_passes(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
        assert not _has(scan_compose(_write(tmp_path, content)), "DC008")

    def test_finding_severity(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    network_mode: host\n"
        )
        f = _get(scan_compose(_write(tmp_path, content)), "DC008")
        assert f is not None and f.severity == "MEDIUM"


# ── DC009 — No resource limits ────────────────────────────────────────────────

class TestDC009:
    def test_no_limits_triggers(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
        assert _has(scan_compose(_write(tmp_path, content)), "DC009")

    def test_mem_limit_and_cpus_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    mem_limit: 512m\n    cpus: '0.5'\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC009")

    def test_deploy_limits_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    deploy:\n      resources:\n        limits:\n"
            "          memory: 512M\n          cpus: '0.5'\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC009")

    def test_finding_severity(self, tmp_path):
        content = "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
        f = _get(scan_compose(_write(tmp_path, content)), "DC009")
        assert f is not None and f.severity == "LOW"


# ── DC010 — Dangerous capabilities ───────────────────────────────────────────

class TestDC010:
    def test_sys_admin_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    cap_add:\n      - SYS_ADMIN\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC010")

    def test_net_admin_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    cap_add:\n      - NET_ADMIN\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC010")

    def test_cap_all_triggers(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    cap_add:\n      - ALL\n"
        )
        assert _has(scan_compose(_write(tmp_path, content)), "DC010")

    def test_safe_capability_passes(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    cap_add:\n      - NET_BIND_SERVICE\n"
        )
        assert not _has(scan_compose(_write(tmp_path, content)), "DC010")

    def test_finding_severity(self, tmp_path):
        content = (
            "version: '3'\nservices:\n  api:\n    image: python:3.12\n"
            "    cap_add:\n      - SYS_ADMIN\n"
        )
        f = _get(scan_compose(_write(tmp_path, content)), "DC010")
        assert f is not None and f.severity == "MEDIUM"


# ── Error handling ────────────────────────────────────────────────────────────

class TestErrorHandling:
    def test_malformed_yaml_raises_value_error(self, tmp_path):
        content = "services:\n  api:\n  broken: [\n"
        with pytest.raises(ValueError, match="Failed to parse"):
            scan_compose(_write(tmp_path, content))

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            scan_compose("/tmp/this_file_does_not_exist_docker_compose.yml")

    def test_non_mapping_root_raises(self, tmp_path):
        content = "- item1\n- item2\n"
        with pytest.raises(ValueError, match="valid docker-compose"):
            scan_compose(_write(tmp_path, content))


# ── Insecure sample integration test ─────────────────────────────────────────

class TestInsecureSample:
    def test_insecure_sample_has_at_least_five_findings(self):
        import os
        sample = os.path.join(
            os.path.dirname(__file__), "samples", "docker-compose.insecure.yml"
        )
        findings = scan_compose(sample)
        assert len(findings) >= 5, (
            f"Expected ≥ 5 findings from insecure sample, got {len(findings)}: "
            + ", ".join(f.rule_id for f in findings)
        )

    def test_secure_sample_has_no_high_findings(self):
        import os
        sample = os.path.join(
            os.path.dirname(__file__), "samples", "docker-compose.secure.yml"
        )
        findings = scan_compose(sample)
        high = [f for f in findings if f.severity == "HIGH"]
        assert high == [], f"Unexpected HIGH findings in secure sample: {[f.rule_id for f in high]}"
