from __future__ import annotations

import io
import json

import pytest

from piiscrub.cli import KEY_ENV, build_parser, run
from tests.conftest import KEY


def call(argv: list[str], text: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(build_parser().parse_args(argv), io.StringIO(text), out, err)
    return code, out.getvalue(), err.getvalue()


def test_text_lines_and_stats() -> None:
    code, out, err = call(["--stats"], "a@example.com\nno pii\n(415) 555-0134")
    assert code == 0
    assert out == "[EMAIL]\nno pii\n[PHONE]"
    assert err == "email\t1\nphone\t1\n"


def test_json_lines_with_fallback() -> None:
    lines = json.dumps({"user": "a@example.com", "password": "p"}) + "\nnot json a@example.com\n"
    code, out, _ = call(["--json"], lines)
    assert code == 0
    first, second = out.splitlines()
    assert json.loads(first) == {"user": "[EMAIL]", "password": "[REDACTED]"}
    assert second == "not json [EMAIL]"


def test_pseudonym_needs_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)
    code, _, err = call(["--mode", "pseudonym"], "x")
    assert code == 2 and KEY_ENV in err
    monkeypatch.setenv(KEY_ENV, KEY.decode())
    code, out, _ = call(["--mode", "pseudonym"], "a@example.com\n")
    assert code == 0 and out.startswith("[email:")


def test_kinds_flag() -> None:
    code, out, _ = call(["--kinds", "ipv4"], "a@example.com 203.0.113.9\n")
    assert out == "a@example.com [IPV4]\n"
    code, _, err = call(["--kinds", "email,bogus"], "")
    assert code == 2 and "bogus" in err
