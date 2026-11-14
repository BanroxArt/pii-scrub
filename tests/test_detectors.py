from __future__ import annotations

import base64
import time

import pytest

from piiscrub import Scrubber
from piiscrub.detectors import KINDS, iban_ok, luhn_ok
from tests.conftest import make_jwt


def kinds(text: str, **kw: object) -> list[tuple[str, str]]:
    s = Scrubber(**kw)  # type: ignore[arg-type]
    return [(f.kind, text[f.start : f.end]) for f in s.scan(text)]


# ------------------------------------------------------------------ email


@pytest.mark.parametrize(
    "text, value",
    [
        ("login jane.doe@example.com ok", "jane.doe@example.com"),
        ("<a+tag@mail.example.org>", "a+tag@mail.example.org"),
        ("to=Ops_Team@example.net;", "Ops_Team@example.net"),
    ],
)
def test_email_found(text: str, value: str) -> None:
    assert kinds(text) == [("email", value)]


@pytest.mark.parametrize(
    "text",
    ["git@github", "a..b@example.com", ".a@example.com", "user@localhost", "x@1.2"],
)
def test_email_not_found(text: str) -> None:
    assert [k for k, _ in kinds(text)] == []


# ------------------------------------------------------------------ phone


@pytest.mark.parametrize(
    "text, value",
    [
        ("call (415) 555-0134 now", "(415) 555-0134"),
        ("call 415-555-0134.", "415-555-0134"),
        ("call 1 415 555 0134", "1 415 555 0134"),
        ("call +1 415 555 0134", "+1 415 555 0134"),
        ("ring +44 20 7946 0958, thanks", "+44 20 7946 0958"),
        ("tel:+14155550134", "+14155550134"),
    ],
)
def test_phone_found(text: str, value: str) -> None:
    assert kinds(text) == [("phone", value)]


@pytest.mark.parametrize(
    "text",
    [
        "order 4155550134",  # bare ten digits: ids, not phones
        "on 2026-11-13 at 10:15",
        "v1.415.555.0134",  # part of a dotted version
        "(115) 555-0134",  # area codes do not start with 0 or 1
        "415-1" + "55-0134",  # nor exchanges (split for the repo lint)
        "+12 34",  # too short for E.164
        "+1234567890123456",  # too long
        "id 415-555-0134-7",
    ],
)
def test_phone_not_found(text: str) -> None:
    assert [k for k, _ in kinds(text)] == []


# ------------------------------------------------------------------ cards


@pytest.mark.parametrize(
    "number",
    ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111", "3782 822463 10005"],
)
def test_card_found(number: str) -> None:
    assert kinds(f"pan {number} exp") == [("card", number)]


def test_card_checks() -> None:
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")
    # Luhn-valid but starts with a digit no card network uses.
    assert kinds("id 1111111111111117 x") == []
    assert kinds("id 4111 1111-1111 1111") == []  # mixed separators
    assert kinds("id 4111111111111112") == []


def test_card_followed_by_more_digits_is_shrunk() -> None:
    assert kinds("4111 1111 1111 1111 22") == [("card", "4111 1111 1111 1111")]


def test_long_digit_runs_are_not_cards() -> None:
    assert kinds("trace 41111111111111111111111111 end") == []


# ------------------------------------------------------------------ SSN


def test_ssn_rules() -> None:
    assert kinds("ssn 219-09-9999.") == [("ssn", "219-09-9999")]
    for never_issued in ("000-12-3456", "666-12-3456", "912-12-3456", "219-00-1234", "219-09-0000"):
        assert kinds(never_issued) == []
    assert kinds("219099999") == []  # no dashes, too ambiguous


# ------------------------------------------------------------------ IBAN


@pytest.mark.parametrize(
    "iban", ["GB82 WEST 1234 5698 7654 32", "GB82WEST12345698765432", "DE89370400440532013000"]
)
def test_iban_found(iban: str) -> None:
    assert kinds(f"pay {iban} today") == [("iban", iban)]


def test_iban_checks() -> None:
    assert iban_ok("GB82WEST12345698765432")
    assert not iban_ok("GB83WEST12345698765432")  # check digits
    assert not iban_ok("GB82WEST1234569876543")  # length for GB
    assert not iban_ok("ZZ82WEST12345698765432")  # unknown country


def test_iban_does_not_swallow_next_word() -> None:
    assert kinds("BE68 5390 0754 7034 SENT") == [("iban", "BE68 5390 0754 7034")]


# ------------------------------------------------------------------ credentials


def test_jwt() -> None:
    token = make_jwt()
    assert kinds(f"jwt={token}") == [("jwt", token)]
    assert kinds(f"Authorization: Bearer {token}") == [("jwt", token)]


def test_auth_header_keeps_scheme() -> None:
    cred = base64.b64encode(b"user:pw").decode()
    assert kinds(f"Authorization: Basic {cred}") == [("auth_header", cred)]
    token = "ab12" * 4
    assert kinds("Bearer " + token) == [("auth_header", token)]


def test_auth_header_ignores_prose() -> None:
    assert kinds("enable basic authentication or bearer tokens") == []


def test_url_password_keeps_user_and_host() -> None:
    assert kinds("dsn=postgres://app:pa55word@db.example.com:5432/x") == [
        ("url_password", "pa55word")
    ]


@pytest.mark.parametrize(
    "text, value",
    [
        ("password=hunter2 next", "hunter2"),
        ("DB_PASSWORD: hunter2", "hunter2"),
        ('{"api_key": "two words"}', "two words"),
        ("x-api-key: abc123;", "abc123"),
        ("client_secret=zz&next=1", "zz"),
        ("refresh-token='r1'", "r1"),
    ],
)
def test_secret_fields(text: str, value: str) -> None:
    assert kinds(text) == [("secret_field", value)]


@pytest.mark.parametrize(
    "text",
    ['"token": null}', "password=${DB_PASSWORD}", "tokens: 5", "token_count=6", 'pwd=""'],
)
def test_secret_field_placeholders(text: str) -> None:
    assert kinds(text) == []


# ------------------------------------------------------------------ ipv4


def test_ipv4_is_opt_in() -> None:
    assert kinds("from 203.0.113.9") == []
    assert kinds("from 203.0.113.9", kinds=["ipv4"]) == [("ipv4", "203.0.113.9")]
    assert kinds("v 256.1.1.1 and 01.2.3.4", kinds=["ipv4"]) == []


# ------------------------------------------------------------------ overlaps


def test_credentials_win_over_pii() -> None:
    assert kinds("password=4111111111111111") == [("secret_field", "4111111111111111")]


def test_email_beats_phone_inside_it() -> None:
    assert [k for k, _ in kinds("+14155550134@example.com")] == ["email"]


# ------------------------------------------------------------------ cost


@pytest.mark.parametrize(
    "text",
    [
        "4" * 100_000,
        "4 " * 50_000,
        "a" * 100_000 + "@",
        ("password" + "=") * 10_000,
        "+1 " * 30_000,
        "GB82 " * 20_000,
        "eyJ" + "a" * 50_000 + ".",
        "Bearer " + "a" * 100_000,
        "a_" * 50_000 + "password",
        "x@" * 50_000,
    ],
)
def test_hostile_input_is_linear_enough(text: str) -> None:
    s = Scrubber(kinds=list(KINDS))
    t0 = time.perf_counter()
    s.scrub(text)
    assert time.perf_counter() - t0 < 5.0
