"""Planted values never survive, and scrubbing twice changes nothing."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from piiscrub import Scrubber
from tests.conftest import KEY, luhn_complete

# Filler with no digits, "@" or "+", so it cannot complete or extend a value.
filler = st.text(alphabet=st.sampled_from("abcdefghij XYZ,;:!?()[]{}<>/\\\"'\n\t"), max_size=40)

cards = st.builds(
    lambda p, body: luhn_complete(p + body),
    st.sampled_from(["4", "51", "37", "6011"]),
    st.text(alphabet="0123456789", min_size=11, max_size=11),
)

emails = st.builds(
    lambda local, host, tld: f"{local}@{host}.{tld}",
    st.from_regex(r"[a-z0-9]{1,8}([._+-][a-z0-9]{1,8}){0,2}", fullmatch=True),
    st.from_regex(r"[a-z]{1,10}(\.[a-z]{1,10})?", fullmatch=True),
    st.sampled_from(["example", "test", "invalid"]),
)

phones = st.builds(
    lambda a, e, n, fmt: fmt.format(a=a, e=e, n=n),
    st.integers(200, 999),
    st.integers(200, 999),
    st.integers(0, 9999).map(lambda n: f"{n:04d}"),
    st.sampled_from(["({a}) {e}-{n}", "{a}-{e}-{n}", "+1 {a} {e} {n}", "{a}.{e}.{n}"]),
)


def surrounded(value: st.SearchStrategy[str]) -> st.SearchStrategy[tuple[str, str]]:
    return st.tuples(filler, value, filler).map(lambda t: (f"{t[0]} {t[1]} {t[2]}", t[1]))


@given(surrounded(cards), st.sampled_from(["mask", "partial", "pseudonym"]))
def test_planted_card_removed(case: tuple[str, str], mode: str) -> None:
    text, card = case
    out = Scrubber(mode=mode, key=KEY).scrub(text)  # type: ignore[arg-type]
    digits = "".join(c for c in out if c.isdigit())
    assert card not in out
    assert card[:-4] not in digits  # partial mode may keep the last four only


@given(surrounded(emails))
def test_planted_email_removed(case: tuple[str, str]) -> None:
    text, email = case
    out = Scrubber(mode="partial").scrub(text)
    assert email.split("@")[0] + "@" not in out


@given(surrounded(phones))
def test_planted_phone_removed(case: tuple[str, str]) -> None:
    text, phone = case
    out = Scrubber().scrub(text)
    assert phone not in out
    assert "[PHONE]" in out


@given(st.text(max_size=200), st.sampled_from(["mask", "partial", "pseudonym"]))
def test_scrub_is_idempotent(text: str, mode: str) -> None:
    s = Scrubber(mode=mode, key=KEY)  # type: ignore[arg-type]
    once = s.scrub(text)
    assert s.scrub(once) == once


@given(st.text(alphabet=st.characters(blacklist_categories=("Nd",)), max_size=200))
def test_text_without_digits_or_at_sign_mostly_unchanged(text: str) -> None:
    # Only credentials can match text with no digits and no "@".
    s = Scrubber(["email", "card", "iban", "ssn", "phone"])
    if "@" not in text:
        assert s.scrub(text) == text


# Pieces that sit close to the patterns' edges, glued in random order.
pieces = st.one_of(
    cards,
    emails,
    phones,
    st.sampled_from(
        [
            " ",
            "-",
            ".",
            "@",
            "+",
            "1",
            "22",
            "0134",
            "password=",
            "Bearer ",
            "GB82 WEST 1234 5698 7654 32",
            "219-09-9999",
            "x",
            ":",
            "//u:",
            "[",
            "]",
        ]
    ),
)


@given(
    st.lists(pieces, max_size=12).map("".join), st.sampled_from(["mask", "partial", "pseudonym"])
)
def test_scrub_is_idempotent_near_pattern_edges(text: str, mode: str) -> None:
    s = Scrubber(mode=mode, key=KEY)  # type: ignore[arg-type]
    once = s.scrub(text)
    assert s.scrub(once) == once
