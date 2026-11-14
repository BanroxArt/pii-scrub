from __future__ import annotations

import pytest

from piiscrub import Scrubber
from piiscrub.detectors import Detector
from tests.conftest import KEY, make_jwt

LINE = "jane@example.com paid with 4111 1111 1111 1111 from (415) 555-0134"


def test_mask() -> None:
    s = Scrubber()
    assert s.scrub(LINE) == "[EMAIL] paid with [CARD] from [PHONE]"
    assert s.counts == {"email": 1, "card": 1, "phone": 1}


def test_partial() -> None:
    s = Scrubber(mode="partial")
    assert s.scrub(LINE) == "[EMAIL ...@example.com] paid with [CARD ...1111] from [PHONE ...34]"
    assert s.scrub("ssn 219-09-9999") == "ssn [SSN]"


def test_pseudonym_is_stable_across_formats() -> None:
    s = Scrubber(mode="pseudonym", key=KEY)
    a = s.scrub("Jane@Example.com 415-555-0134 4111111111111111")
    b = s.scrub("jane@example.com +1 (415) 555-0134 4111-1111-1111-1111")
    assert a == b
    assert a.startswith("[email:") and "[phone:" in a and "[card:" in a


def test_pseudonym_depends_on_key_and_kind() -> None:
    a = Scrubber(mode="pseudonym", key=KEY).scrub("jane@example.com")
    b = Scrubber(mode="pseudonym", key=KEY + b"2").scrub("jane@example.com")
    assert a != b


def test_pseudonym_needs_a_real_key() -> None:
    with pytest.raises(ValueError, match="key"):
        Scrubber(mode="pseudonym")
    with pytest.raises(ValueError, match="key"):
        Scrubber(mode="pseudonym", key=b"short")


@pytest.mark.parametrize("mode", ["mask", "partial", "pseudonym"])
def test_credentials_always_masked(mode: str) -> None:
    s = Scrubber(mode=mode, key=KEY)  # type: ignore[arg-type]
    token = make_jwt()
    out = s.scrub(f"password=hunter2 jwt {token}")
    assert out == "password=[REDACTED] jwt [REDACTED]"


def test_unknown_kind_and_mode() -> None:
    with pytest.raises(ValueError, match="unknown kinds: nope"):
        Scrubber(["email", "nope"])
    with pytest.raises(ValueError, match="mode"):
        Scrubber(mode="hash")  # type: ignore[arg-type]


def test_repr_does_not_show_key() -> None:
    r = repr(Scrubber(mode="pseudonym", key=KEY))
    assert KEY.decode() not in r and "key=set" in r


def test_extra_detector() -> None:
    import re

    order = Detector("order_id", re.compile(r"\bORD-[0-9]{8}\b"), priority=5)
    s = Scrubber(["email"], extra=[order])
    assert s.scrub("ORD-12345678 for a@example.com") == "[ORDER_ID] for [EMAIL]"


def test_text_without_findings_is_returned_as_is() -> None:
    s = Scrubber()
    text = "GET /health 200 3ms"
    assert s.scrub(text) is text


# ------------------------------------------------------------------ structures


def test_scrub_obj() -> None:
    s = Scrubber()
    doc = {
        "user": {"email": "jane@example.com", "Password": 1234},
        "headers": {"Authorization": "Bearer x", "X-Request-Id": "r1"},
        "notes": ["call 415-555-0134", ("t", "a@example.com")],
        "jane@example.com": True,
        "count": 3,
        "raw": b"to a@example.com",
    }
    assert s.scrub_obj(doc) == {
        "user": {"email": "[EMAIL]", "Password": "[REDACTED]"},
        "headers": {"Authorization": "[REDACTED]", "X-Request-Id": "r1"},
        "notes": ["call [PHONE]", ("t", "[EMAIL]")],
        "[EMAIL]": True,
        "count": 3,
        "raw": b"to [EMAIL]",
    }
    assert doc["user"]["email"] == "jane@example.com"  # type: ignore[index]


def test_scrub_obj_depth_limit() -> None:
    s = Scrubber(max_depth=3)
    deep: object = "a@example.com"
    for _ in range(10):
        deep = [deep]
    out = s.scrub_obj(deep)
    for _ in range(4):
        out = out[0]
    assert out == "[TRUNCATED]"


def test_custom_sensitive_keys() -> None:
    s = Scrubber(sensitive_keys={"dob"})
    assert s.scrub_obj({"DOB": "1990-01-01", "password": "x"}) == {
        "DOB": "[REDACTED]",
        "password": "x",
    }
