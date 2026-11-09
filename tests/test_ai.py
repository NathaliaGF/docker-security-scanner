"""AI layer tests with a fake client: no network, no API key."""

from types import SimpleNamespace

from dockerscan.ai import REDACTED, explain, propose_fix, redact
from dockerscan.core import scan_text

BAD = "FROM python:latest\nENV DB_PASSWORD=hunter2\nCMD [\"python\"]\n"
GOOD = "FROM python:3.12-slim\nENV DB_PASSWORD=${DB_PASSWORD}\nRUN useradd -r app\nUSER app\nCMD [\"python\"]\n"


class FakeClient:
    """Returns canned replies in order and records the prompts it received."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.prompts.append(kwargs["messages"][0]["content"])
        text = self.replies.pop(0)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


def _fenced(text):
    return f"Here you go:\n```dockerfile\n{text}```\n"


class TestRedact:
    def test_masks_values_not_names(self):
        out = redact("ENV DB_PASSWORD=hunter2\nENV API_KEY abc\n  - SECRET_TOKEN=x\nFROM a\n")
        assert "hunter2" not in out and "abc" not in out and "=x" not in out
        assert f"DB_PASSWORD={REDACTED}" in out
        assert "FROM a" in out

    def test_compose_mapping_style(self):
        assert "s3cr3t" not in redact("    POSTGRES_PASSWORD: s3cr3t\n")


class TestExplain:
    def test_secret_never_reaches_prompt(self, tmp_path):
        client = FakeClient("explained")
        findings = scan_text(BAD, "Dockerfile")
        assert explain("Dockerfile", BAD, findings, client) == "explained"
        assert "hunter2" not in client.prompts[0]
        assert "DF003" in client.prompts[0]


class TestProposeFix:
    def _write(self, tmp_path, text):
        p = tmp_path / "Dockerfile"
        p.write_text(text)
        return str(p)

    def test_accepts_validated_fix(self, tmp_path):
        path = self._write(tmp_path, BAD)
        before = scan_text(BAD, "Dockerfile")
        result = propose_fix(path, BAD, before, FakeClient(_fenced(GOOD)))
        assert result.accepted
        assert len(result.after) < len(result.before)
        assert "-FROM python:latest" in result.diff

    def test_rejects_fix_that_keeps_the_marker(self, tmp_path):
        path = self._write(tmp_path, BAD)
        leaked = GOOD.replace("${DB_PASSWORD}", REDACTED)
        result = propose_fix(path, BAD, scan_text(BAD, "Dockerfile"),
                             FakeClient(_fenced(leaked), _fenced(leaked)))
        assert not result.accepted

    def test_rejects_fix_that_makes_things_worse(self, tmp_path):
        path = self._write(tmp_path, "FROM python:3.12\nUSER app\n")
        before = scan_text("FROM python:3.12\nUSER app\n", "Dockerfile")
        worse = "FROM python:latest\nUSER root\n"
        result = propose_fix(path, "FROM python:3.12\nUSER app\n", before,
                             FakeClient(_fenced(worse), _fenced(worse)))
        assert not result.accepted

    def test_retries_with_remaining_findings(self, tmp_path):
        path = self._write(tmp_path, BAD)
        half = "FROM python:3.12-slim\nENV DB_PASSWORD=${DB_PASSWORD}\nCMD [\"python\"]\n"
        client = FakeClient(_fenced(half), _fenced(GOOD))
        result = propose_fix(path, BAD, scan_text(BAD, "Dockerfile"), client)
        assert result.attempts == 2 and result.accepted
        assert "DF001" in client.prompts[1]  # second prompt lists what is still wrong

    def test_reply_without_code_block(self, tmp_path):
        path = self._write(tmp_path, BAD)
        result = propose_fix(path, BAD, scan_text(BAD, "Dockerfile"), FakeClient("sorry"))
        assert not result.accepted and "code block" in result.reason
