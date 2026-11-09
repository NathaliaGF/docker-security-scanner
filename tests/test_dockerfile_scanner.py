"""
Unit tests for the Dockerfile scanner — one test class per DF rule.
"""

import os

import pytest

from dockerscan import Finding
from dockerscan.dockerfile_scanner import scan_dockerfile

# ── Helpers ───────────────────────────────────────────────────────────────────

def _write(tmp_path, content: str, name: str = "Dockerfile") -> str:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


def _has(findings: list[Finding], rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


def _get(findings: list[Finding], rule_id: str) -> Finding | None:
    return next((f for f in findings if f.rule_id == rule_id), None)


# ── DF001 — Running as root ───────────────────────────────────────────────────

class TestDF001:
    def test_no_user_instruction_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nRUN echo hello\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF001")

    def test_explicit_user_root_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nUSER root\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF001")

    def test_user_zero_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nUSER 0\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF001")

    def test_non_root_user_passes(self, tmp_path):
        content = "FROM python:3.12-slim\nUSER appuser\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF001")

    def test_uid_nonzero_passes(self, tmp_path):
        content = "FROM python:3.12-slim\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF001")

    def test_finding_severity(self, tmp_path):
        content = "FROM python:3.12-slim\n"
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF001")
        assert f is not None and f.severity == "HIGH"


# ── DF002 — Base image with latest tag ───────────────────────────────────────

class TestDF002:
    def test_latest_tag_triggers(self, tmp_path):
        content = "FROM python:latest\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF002")

    def test_no_tag_triggers(self, tmp_path):
        content = "FROM python\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF002")

    def test_pinned_tag_passes(self, tmp_path):
        content = "FROM python:3.12-slim\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF002")

    def test_scratch_passes(self, tmp_path):
        content = "FROM scratch\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF002")

    def test_multistage_both_checked(self, tmp_path):
        content = "FROM python:latest AS builder\nFROM python:3.12-slim\nUSER 1000\n"
        findings = scan_dockerfile(_write(tmp_path, content))
        df002 = [f for f in findings if f.rule_id == "DF002"]
        assert len(df002) >= 1

    def test_finding_severity(self, tmp_path):
        content = "FROM python:latest\nUSER 1000\n"
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF002")
        assert f is not None and f.severity == "MEDIUM"


# ── DF003 — Hardcoded credentials ────────────────────────────────────────────

class TestDF003:
    def test_env_password_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nENV PASSWORD=secret123\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF003")

    def test_env_secret_key_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nENV SECRET_KEY=supersecret\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF003")

    def test_arg_api_key_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nARG API_KEY=sk-prod-1234\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF003")

    def test_env_token_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nENV TOKEN=ghp_abc123\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF003")

    def test_safe_env_passes(self, tmp_path):
        content = "FROM python:3.12-slim\nENV APP_PORT=8080\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF003")

    def test_arg_no_default_passes(self, tmp_path):
        # ARG PASSWORD without a default value is a build arg, not a baked secret.
        content = "FROM python:3.12-slim\nARG PASSWORD\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF003")

    def test_finding_severity(self, tmp_path):
        content = "FROM python:3.12-slim\nENV PASSWORD=secret\nUSER 1000\n"
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF003")
        assert f is not None and f.severity == "HIGH"


# ── DF004 — apt-get without --no-install-recommends ──────────────────────────

class TestDF004:
    def test_apt_install_without_flag_triggers(self, tmp_path):
        content = "FROM ubuntu:22.04\nRUN apt-get install -y curl\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF004")

    def test_apt_install_with_flag_passes(self, tmp_path):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN apt-get install -y --no-install-recommends curl\n"
            "USER 1000\n"
        )
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF004")

    def test_non_apt_run_passes(self, tmp_path):
        content = "FROM ubuntu:22.04\nRUN echo hello\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF004")

    def test_finding_severity(self, tmp_path):
        content = "FROM ubuntu:22.04\nRUN apt-get install -y curl\nUSER 1000\n"
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF004")
        assert f is not None and f.severity == "MEDIUM"


# ── DF005 — COPY . . ─────────────────────────────────────────────────────────

class TestDF005:
    def test_copy_dot_dot_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY . .\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF005")

    def test_copy_dot_slash_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY ./ /app/\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF005")

    def test_copy_specific_path_passes(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY src/ /app/src/\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF005")

    def test_copy_requirements_passes(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY requirements.txt .\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF005")

    def test_finding_severity(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY . .\nUSER 1000\n"
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF005")
        assert f is not None and f.severity == "LOW"


# ── DF006 — curl | bash ───────────────────────────────────────────────────────

class TestDF006:
    def test_curl_pipe_bash_triggers(self, tmp_path):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN curl -fsSL https://get.docker.com | bash\n"
            "USER 1000\n"
        )
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF006")

    def test_wget_pipe_sh_triggers(self, tmp_path):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN wget -qO- https://example.com/install.sh | sh\n"
            "USER 1000\n"
        )
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF006")

    def test_curl_without_pipe_passes(self, tmp_path):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN curl -O https://example.com/package.tar.gz\n"
            "USER 1000\n"
        )
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF006")

    def test_finding_severity(self, tmp_path):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN curl https://example.com/setup.sh | bash\n"
            "USER 1000\n"
        )
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF006")
        assert f is not None and f.severity == "MEDIUM"


# ── DF007 — Multiple consecutive RUN instructions ────────────────────────────

class TestDF007:
    def test_more_than_three_run_triggers(self, tmp_path):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN apt-get update\n"
            "RUN apt-get install -y --no-install-recommends curl\n"
            "RUN apt-get install -y --no-install-recommends wget\n"
            "RUN apt-get install -y --no-install-recommends git\n"
            "USER 1000\n"
        )
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF007")

    def test_exactly_three_run_passes(self, tmp_path):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN apt-get update\n"
            "RUN apt-get install -y --no-install-recommends curl\n"
            "RUN apt-get install -y --no-install-recommends wget\n"
            "USER 1000\n"
        )
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF007")

    def test_non_consecutive_runs_pass(self, tmp_path):
        # COPY in between breaks the streak.
        content = (
            "FROM ubuntu:22.04\n"
            "RUN apt-get update\n"
            "RUN apt-get install -y --no-install-recommends curl\n"
            "COPY requirements.txt .\n"
            "RUN pip install -r requirements.txt\n"
            "RUN pip install gunicorn\n"
            "USER 1000\n"
        )
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF007")

    def test_finding_severity(self, tmp_path):
        content = (
            "FROM ubuntu:22.04\n"
            "RUN a\nRUN b\nRUN c\nRUN d\n"
            "USER 1000\n"
        )
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF007")
        assert f is not None and f.severity == "LOW"


# ── DF008 — Sensitive port exposed ───────────────────────────────────────────

class TestDF008:
    def test_expose_22_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nEXPOSE 22\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF008")

    def test_expose_23_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nEXPOSE 23\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF008")

    def test_expose_3389_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nEXPOSE 3389\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF008")

    def test_expose_8080_passes(self, tmp_path):
        content = "FROM python:3.12-slim\nEXPOSE 8080\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF008")

    def test_finding_severity(self, tmp_path):
        content = "FROM python:3.12-slim\nEXPOSE 22\nUSER 1000\n"
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF008")
        assert f is not None and f.severity == "MEDIUM"


# ── DF009 — Private key copied ───────────────────────────────────────────────

class TestDF009:
    def test_copy_pem_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY server.pem /etc/ssl/\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF009")

    def test_copy_id_rsa_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY id_rsa /root/.ssh/\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF009")

    def test_copy_key_file_triggers(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY private.key /app/\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF009")

    def test_copy_safe_file_passes(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY app.py /app/\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF009")

    def test_finding_severity(self, tmp_path):
        content = "FROM python:3.12-slim\nCOPY id_rsa /root/.ssh/\nUSER 1000\n"
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF009")
        assert f is not None and f.severity == "HIGH"


# ── DF010 — End-of-life base image ───────────────────────────────────────────

class TestDF010:
    def test_ubuntu_1604_triggers(self, tmp_path):
        content = "FROM ubuntu:16.04\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF010")

    def test_debian_jessie_triggers(self, tmp_path):
        content = "FROM debian:jessie\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF010")

    def test_python_27_triggers(self, tmp_path):
        content = "FROM python:2.7\nUSER 1000\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF010")

    def test_ubuntu_2204_passes(self, tmp_path):
        content = "FROM ubuntu:22.04\nUSER 1000\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF010")

    def test_finding_severity(self, tmp_path):
        content = "FROM ubuntu:16.04\nUSER 1000\n"
        f = _get(scan_dockerfile(_write(tmp_path, content)), "DF010")
        assert f is not None and f.severity == "LOW"


# ── Error handling ────────────────────────────────────────────────────────────

class TestErrorHandling:
    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            scan_dockerfile("/tmp/this_does_not_exist_Dockerfile")


# ── Insecure sample integration test ─────────────────────────────────────────

class TestInsecureSample:
    def test_insecure_dockerfile_has_many_findings(self):
        sample = os.path.join(
            os.path.dirname(__file__), "samples", "Dockerfile.insecure"
        )
        findings = scan_dockerfile(sample)
        assert len(findings) >= 5, (
            f"Expected ≥ 5 findings, got {len(findings)}: "
            + ", ".join(f.rule_id for f in findings)
        )

    def test_secure_dockerfile_has_no_high_findings(self):
        sample = os.path.join(
            os.path.dirname(__file__), "samples", "Dockerfile.secure"
        )
        findings = scan_dockerfile(sample)
        high = [f for f in findings if f.severity == "HIGH"]
        assert high == [], f"Unexpected HIGH findings: {[f.rule_id for f in high]}"


# ── Regression: false positives found while building the AI fix validator ────

class TestVariableReferencesAreNotSecrets:
    @pytest.mark.parametrize("line", [
        "ENV DB_PASSWORD=${DB_PASSWORD}",
        "ENV DB_PASSWORD=$DB_PASSWORD",
        "ARG API_TOKEN=${API_TOKEN:-}",
        "ENV DB_PASSWORD $DB_PASSWORD",
    ])
    def test_reference_not_flagged(self, tmp_path, line):
        content = f"FROM python:3.12\n{line}\nUSER app\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF003")

    def test_literal_still_flagged(self, tmp_path):
        content = "FROM python:3.12\nENV DB_PASSWORD=hunter2\nUSER app\n"
        assert _has(scan_dockerfile(_write(tmp_path, content)), "DF003")


class TestDF005HonoursDockerignore:
    def test_not_flagged_with_dockerignore(self, tmp_path):
        (tmp_path / ".dockerignore").write_text(".git\n")
        content = "FROM python:3.12\nCOPY . .\nUSER app\n"
        assert not _has(scan_dockerfile(_write(tmp_path, content)), "DF005")
