"""Tests for file detection, directory collection, SARIF/Markdown and the CLI."""

import json
import os

import pytest

from dockerscan.cli import main
from dockerscan.core import collect_targets, detect_type, scan_text
from dockerscan.references import cis_reference
from dockerscan.rules import COMPOSE_RULES, DOCKERFILE_RULES
from dockerscan.sarif import to_markdown, to_sarif

SAMPLES = os.path.join(os.path.dirname(__file__), "samples")
INSECURE = os.path.join(SAMPLES, "Dockerfile.insecure")
SECURE = os.path.join(SAMPLES, "Dockerfile.secure")


class TestDetection:
    def test_by_name(self):
        assert detect_type("a/docker-compose.prod.yml") == "compose"
        assert detect_type("a/Dockerfile.dev") == "dockerfile"

    def test_non_yaml_extension_is_not_sniffed(self, tmp_path):
        p = tmp_path / "notes.txt"
        p.write_text("FROM ubuntu\n")
        assert detect_type(str(p)) == "unknown"

    def test_collect_skips_vendor_dirs(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
        vendored = tmp_path / "node_modules" / "x"
        vendored.mkdir(parents=True)
        (vendored / "Dockerfile").write_text("FROM python:3.12\n")
        assert collect_targets(str(tmp_path)) == [str(tmp_path / "Dockerfile")]


class TestScanText:
    def test_matches_file_scan(self):
        with open(INSECURE, encoding="utf-8") as fh:
            findings = scan_text(fh.read(), "Dockerfile")
        assert any(f.rule_id == "DF003" for f in findings)

    def test_mirrors_dockerignore(self, tmp_path):
        (tmp_path / ".dockerignore").write_text(".git\n")
        content = "FROM python:3.12\nUSER app\nCOPY . .\n"
        ids = {f.rule_id for f in scan_text(content, "Dockerfile", str(tmp_path))}
        assert "DF005" not in ids
        ids = {f.rule_id for f in scan_text(content, "Dockerfile")}
        assert "DF005" in ids


class TestReferences:
    def test_known_and_unknown(self):
        assert cis_reference("DC007").startswith("CIS Docker Benchmark 5.4")
        assert cis_reference("DC003") is None

    def test_every_mapped_rule_exists(self):
        from dockerscan.references import CIS_DOCKER
        assert set(CIS_DOCKER) <= set(COMPOSE_RULES) | set(DOCKERFILE_RULES)


class TestSarif:
    def test_structure(self):
        from dockerscan.core import scan_file
        sarif = to_sarif([(INSECURE, scan_file(INSECURE))])
        run = sarif["runs"][0]
        assert sarif["version"] == "2.1.0"
        assert len(run["tool"]["driver"]["rules"]) == 20
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        assert run["results"] and all(r["ruleId"] in rule_ids for r in run["results"])
        assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
                   for r in run["results"])

    def test_severity_filter(self):
        from dockerscan.core import scan_file
        sarif = to_sarif([(INSECURE, scan_file(INSECURE))], "LOW")
        assert {r["level"] for r in sarif["runs"][0]["results"]} == {"note"}

    def test_markdown_escapes_pipes(self):
        from dockerscan.core import scan_file
        md = to_markdown([(INSECURE, scan_file(INSECURE))])
        assert "curl \\| bash" in md


class TestCli:
    def test_exit_1_on_high(self, capsys):
        assert main(["--file", INSECURE]) == 1

    def test_exit_0_on_secure(self, capsys):
        assert main(["--file", SECURE]) == 0

    def test_fail_on_none(self, capsys):
        assert main(["--file", INSECURE, "--fail-on", "none"]) == 0

    def test_fail_on_medium_catches_medium_only_files(self, tmp_path, capsys):
        p = tmp_path / "Dockerfile"
        p.write_text("FROM python:latest\nUSER app\n")
        assert main(["--file", str(p)]) == 0
        assert main(["--file", str(p), "--fail-on", "MEDIUM"]) == 1

    def test_dir_json_is_one_valid_document(self, capsys):
        main(["--dir", SAMPLES, "--output", "json", "--fail-on", "none"])
        doc = json.loads(capsys.readouterr().out)
        assert len(doc["files"]) == 4

    def test_file_json_schema_unchanged(self, capsys):
        main(["--file", SECURE, "--output", "json"])
        doc = json.loads(capsys.readouterr().out)
        assert {"file", "score", "total_findings", "findings", "summary"} <= set(doc)

    def test_missing_file_is_exit_2(self, capsys):
        assert main(["--file", "/nope/Dockerfile"]) == 2

    def test_list_rules(self, capsys):
        assert main(["--list-rules"]) == 0
        assert capsys.readouterr().out.count("\n") == 20

    def test_explain_without_key_is_clear_error(self, monkeypatch, capsys):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert main(["--file", INSECURE, "--explain"]) == 2
        assert "ANTHROPIC_API_KEY" in capsys.readouterr().err

    def test_ai_flags_reject_machine_formats(self):
        with pytest.raises(SystemExit):
            main(["--file", INSECURE, "--fix", "--output", "json"])

    def test_apply_requires_fix(self):
        with pytest.raises(SystemExit):
            main(["--file", INSECURE, "--apply"])
