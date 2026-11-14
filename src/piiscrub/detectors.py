"""What counts as sensitive, and how each match is checked before redaction.

Every detector is a regular expression that finds candidates plus a
validator that throws out the ones that only look right. The validators are
what keep false positives down: a run of 16 digits in a log is usually an
order id, not a card, unless it passes the Luhn check and starts with a
digit card networks use.

Patterns are written so that the regex engine cannot backtrack badly on
hostile input: no nested unbounded quantifiers, and every repetition is over
a character class with an upper bound. ``tests/test_detectors.py`` times
the worst inputs we know of.

Detectors that find credentials (``SECRET_KINDS``) name the group holding
the value, so ``Authorization: Bearer <token>`` keeps the word ``Bearer``
and loses the token.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

Validator = Callable[[str], bool]
Normaliser = Callable[[str], str]


def _digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def _always(_: str) -> bool:
    return True


def _identity(s: str) -> str:
    return s


@dataclass(frozen=True)
class Detector:
    """One kind of sensitive value.

    ``group`` is the regex group to redact (0 for the whole match).
    ``priority`` breaks ties when two detectors claim overlapping text of the
    same length; lower wins.
    """

    kind: str
    pattern: re.Pattern[str]
    validate: Validator = _always
    normalise: Normaliser = _identity
    group: int | str = 0
    priority: int = 50
    # Retry shorter matches when the longest fails validation: a greedy
    # IBAN or card match can swallow the next word or number.
    shrink: bool = False


# ---------------------------------------------------------------- email

EMAIL_RE = re.compile(
    r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}(?![\w-])"
)


def _email_ok(s: str) -> bool:
    local = s.split("@", 1)[0]
    return not (local.startswith(".") or local.endswith(".") or ".." in local)


# ---------------------------------------------------------------- phone
# Two shapes. International numbers must start with "+": without it, a
# bare run of digits is far more often an id than a phone number. North
# American numbers are accepted without "+1" when they carry separators.

PHONE_RE = re.compile(
    r"(?<![\w+.-])(?:"
    r"\+[1-9][0-9 ().-]{6,20}[0-9]"
    r"|(?:1[ .-])?(?:\([2-9][0-9]{2}\) ?|[2-9][0-9]{2}[ .-])[2-9][0-9]{2}[ .-][0-9]{4}"
    r")(?![\w-]|\.[0-9])"
)


def _phone_ok(s: str) -> bool:
    d = _digits(s)
    if s.startswith("+"):
        if not 8 <= len(d) <= 15:
            return False
        # A separator run like "1 - - 2" is not how anyone writes a number.
        return re.search(r"[ ().-]{3}", s) is None
    if len(d) == 11:
        d = d[1:]
    return len(d) == 10


def _phone_norm(s: str) -> str:
    d = _digits(s)
    if not s.startswith("+") and len(d) == 10:
        d = "1" + d
    return "+" + d


# ---------------------------------------------------------------- payment card

CARD_RE = re.compile(r"(?<![\w.-])[2-6](?:[ -]?[0-9]){12,18}(?![\w-]|\.[0-9])")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _card_ok(s: str) -> bool:
    d = _digits(s)
    if not 13 <= len(d) <= 19 or not luhn_ok(d):
        return False
    # Mixed separators ("4111 1111-1111 1111") are almost never a card.
    return not (" " in s and "-" in s)


# ---------------------------------------------------------------- US SSN
# Dashes required: nine bare digits match too much. Numbers the SSA never
# issues (area 000, 666 or 9xx, group 00, serial 0000) are left alone.

SSN_RE = re.compile(r"(?<![\w-])([0-9]{3})-([0-9]{2})-([0-9]{4})(?![\w-])")


def _ssn_ok(s: str) -> bool:
    area, group, serial = s.split("-")
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


# ---------------------------------------------------------------- IBAN

IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}  # fmt: skip

IBAN_RE = re.compile(r"(?<![\w])[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}(?![\w])")


def _compact(s: str) -> str:
    return s.replace(" ", "")


def iban_ok(s: str) -> bool:
    compact = s.replace(" ", "")
    if IBAN_LENGTHS.get(compact[:2]) != len(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(c, 36)) for c in rearranged)
    return int(number) % 97 == 1


# ---------------------------------------------------------------- credentials

# Three base64url segments, the first two JSON objects ("eyJ" is "{").
JWT_RE = re.compile(
    r"(?<![\w-])eyJ[A-Za-z0-9_-]{4,8192}\.eyJ[A-Za-z0-9_-]{4,8192}\.[A-Za-z0-9_-]{0,8192}(?![\w-])"
)

AUTH_RE = re.compile(r"(?i)\b(?:bearer|basic)[ \t]+(?P<v>[A-Za-z0-9._~+/=-]{8,4096})(?![\w~+/=-])")

# scheme://user:password@host keeps the user and host.
URL_CRED_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@]{1,256}:(?P<v>[^\s/@]{1,256})@")

SECRET_KEY_NAMES = (
    r"password|passwd|pwd|passphrase|secret|client[_-]?secret|api[_-]?key|apikey"
    r"|access[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token"
    r"|auth[_-]?token|id[_-]?token|session[_-]?id|token"
)
# key=value, key: value, "key": "value". A quoted value runs to the
# closing quote, spaces and all. An unquoted one stops at whitespace, a
# quote, the separators of query strings and cookies, or a closing bracket
# (so "token": null} is read as null); a bare password containing "}" or
# "]" therefore keeps its tail. Quote it, or scrub the structure with
# scrub_obj, which replaces the whole value.
KV_SECRET_RE = re.compile(
    r"(?i)(?<![\w-])[\"']?(?:[\w-]{0,40}[_-])?(?:" + SECRET_KEY_NAMES + r")[\"']?"
    r"[ \t]{0,4}[=:][ \t]{0,4}[\"']?"
    r"(?P<v>(?<=\")[^\"\n]{1,4096}(?=\")|(?<=')[^'\n]{1,4096}(?=')|[^\s\"'&,;}\]]{1,4096})"
)


# Our own replacement tokens, cut where an unquoted value stops.
_TOKEN_RE = re.compile(r"\[(?:[A-Z_]+(?: |$)|[a-z_]+:[0-9a-f]{12}$)")


def _kv_ok(s: str) -> bool:
    # "token: null", empty password values, template variables and values
    # this package already replaced are noise.
    if s.lower() in ("null", "none", "true", "false", "***", "redacted"):
        return False
    return not (s.startswith(("${", "{{", "<")) or _TOKEN_RE.match(s))


def _auth_ok(s: str) -> bool:
    # "basic authentication" is prose; a credential has a digit, a symbol
    # or mixed case.
    if not _kv_ok(s):
        return False
    return any(not c.isalpha() for c in s) or (s.lower() != s and s.upper() != s)


# ---------------------------------------------------------------- ipv4 (opt-in)

IPV4_RE = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w]|\.[0-9])")


def _ipv4_ok(s: str) -> bool:
    return all(int(p) <= 255 and (p == "0" or not p.startswith("0")) for p in s.split("."))


KINDS: dict[str, Detector] = {
    d.kind: d
    for d in (
        Detector("jwt", JWT_RE, priority=10),
        Detector("auth_header", AUTH_RE, _auth_ok, group="v", priority=11),
        Detector("url_password", URL_CRED_RE, group="v", priority=12),
        Detector("secret_field", KV_SECRET_RE, _kv_ok, group="v", priority=13),
        Detector("email", EMAIL_RE, _email_ok, str.lower, priority=20),
        Detector("card", CARD_RE, _card_ok, _digits, priority=30, shrink=True),
        Detector("iban", IBAN_RE, iban_ok, _compact, priority=31, shrink=True),
        Detector("ssn", SSN_RE, _ssn_ok, _digits, priority=32),
        Detector("phone", PHONE_RE, _phone_ok, _phone_norm, priority=40, shrink=True),
        Detector("ipv4", IPV4_RE, _ipv4_ok, priority=60),
    )
}

SECRET_KINDS = frozenset({"jwt", "auth_header", "url_password", "secret_field"})
# IPv4 addresses are personal data in some jurisdictions, but most
# operational logs need them; turn the detector on when yours do not.
DEFAULT_KINDS = tuple(k for k in KINDS if k != "ipv4")
