"""Find sensitive values in text and replace them.

Three replacement modes:

``mask``
    ``[EMAIL]``, ``[CARD]``. Nothing about the value survives.
``partial``
    Keeps what support staff usually need to match a record and nothing that
    identifies the person on its own: the last four digits of a card or
    IBAN, the last two of a phone number, the domain of an email.
``pseudonym``
    ``[email:5d41402abc4b]``: a keyed HMAC of the normalised value, so the
    same customer shows the same token across log lines and services that
    share the key, and nobody without the key can test a guess. An unkeyed
    hash would be no protection at all; there are only 10^10 North American
    phone numbers, and a laptop hashes them in minutes. The key is
    therefore required for this mode.

Credentials (``SECRET_KINDS``) are always masked whatever the mode. A
pseudonym of a password still tells a reader that two services share it.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from piiscrub.detectors import DEFAULT_KINDS, KINDS, SECRET_KINDS, Detector

Mode = Literal["mask", "partial", "pseudonym"]
MODES: tuple[Mode, ...] = ("mask", "partial", "pseudonym")
MIN_KEY_BYTES = 16
PSEUDONYM_HEX = 12
MAX_PASSES = 4

# Field names whose whole value is replaced, in mappings passed to
# scrub_obj. Matching is on the lower-cased name with "-" read as "_".
DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "access_key",
        "secret_key",
        "private_key",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "session",
        "session_id",
        "x_api_key",
    }
)

_WORD_END = re.compile(r"[A-Za-z0-9]")


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int

    @property
    def secret(self) -> bool:
        return self.kind in SECRET_KINDS


class Scrubber:
    """Detect and replace sensitive values.

    ``kinds`` picks detectors by name (see ``KINDS``); ``extra`` adds your
    own. ``counts`` totals replacements by kind since construction, for a
    metric that shows the scrubber is doing something.

    Thread-safe for scanning; ``counts`` updates are not atomic across
    threads, so treat them as approximate under concurrency.
    """

    def __init__(
        self,
        kinds: Iterable[str] = DEFAULT_KINDS,
        *,
        mode: Mode = "mask",
        key: bytes | None = None,
        sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
        extra: Iterable[Detector] = (),
        max_depth: int = 32,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {', '.join(MODES)}")
        if mode == "pseudonym" and (key is None or len(key) < MIN_KEY_BYTES):
            raise ValueError(f"pseudonym mode needs a key of at least {MIN_KEY_BYTES} bytes")
        kinds = list(kinds)
        unknown = [k for k in kinds if k not in KINDS]
        if unknown:
            raise ValueError(f"unknown kinds: {', '.join(unknown)}")
        self.detectors = sorted([KINDS[k] for k in kinds] + list(extra), key=lambda d: d.priority)
        self.mode: Mode = mode
        self._key = key
        self.sensitive_keys = frozenset(_norm_key(k) for k in sensitive_keys)
        self.max_depth = max_depth
        self.counts: Counter[str] = Counter()

    def __repr__(self) -> str:
        kinds = ",".join(d.kind for d in self.detectors)
        return f"Scrubber(kinds={kinds}, mode={self.mode}, key={'set' if self._key else 'none'})"

    # ------------------------------------------------------------ scanning

    def scan(self, text: str) -> list[Finding]:
        """Non-overlapping findings in text order.

        Higher-priority detectors claim text first (credentials, then
        email, then numbers); a lower-priority match overlapping a claimed
        span is dropped rather than cut, so no fragment of it survives
        next to the replacement.
        """
        taken: list[Finding] = []
        for det in self.detectors:
            for f in self._candidates(det, text):
                if not any(f.start < t.end and t.start < f.end for t in taken):
                    taken.append(f)
        taken.sort(key=lambda f: f.start)
        return taken

    def _candidates(self, det: Detector, text: str) -> Iterable[Finding]:
        for m in det.pattern.finditer(text):
            start, end = m.span(det.group)
            if start < 0:
                continue
            if det.validate(text[start:end]):
                yield Finding(det.kind, start, end)
            elif det.shrink:
                found = self._shrink(det, text, m.start(), m.end())
                if found is not None:
                    yield found

    @staticmethod
    def _shrink(det: Detector, text: str, start: int, end: int) -> Finding | None:
        for pos in range(end - 1, start, -1):
            if not (_WORD_END.match(text[pos - 1]) and not _WORD_END.match(text[pos])):
                continue
            if det.pattern.fullmatch(text, start, pos) and det.validate(text[start:pos]):
                return Finding(det.kind, start, pos)
        return None

    # ------------------------------------------------------------ replacing

    def scrub(self, text: str) -> str:
        """Replace every finding, then look again.

        A match removed in one pass can expose its neighbour: in
        ``4000000000006(415) 555-0100`` the phone number is glued to a card
        and fails its own boundary check until the card is gone. Passes
        repeat until nothing more is found (two in practice; capped at
        ``MAX_PASSES``). Replacement tokens never match a detector, so the
        loop always ends.
        """
        for _ in range(MAX_PASSES):
            out = self._scrub_once(text)
            if out is text:
                break
            text = out
        return text

    def _scrub_once(self, text: str) -> str:
        findings = self.scan(text)
        if not findings:
            return text
        out: list[str] = []
        pos = 0
        for f in findings:
            out.append(text[pos : f.start])
            out.append(self.replacement(f.kind, text[f.start : f.end]))
            pos = f.end
            self.counts[f.kind] += 1
        out.append(text[pos:])
        return "".join(out)

    def replacement(self, kind: str, value: str) -> str:
        if kind in SECRET_KINDS or self.mode == "mask":
            return "[REDACTED]" if kind in SECRET_KINDS else f"[{kind.upper()}]"
        det = KINDS.get(kind)
        norm = det.normalise(value) if det else value
        if self.mode == "pseudonym":
            assert self._key is not None
            mac = hmac.new(self._key, f"{kind}:{norm}".encode(), hashlib.sha256)
            return f"[{kind}:{mac.hexdigest()[:PSEUDONYM_HEX]}]"
        hint = _partial(kind, norm)
        return f"[{kind.upper()} {hint}]" if hint else f"[{kind.upper()}]"

    # ------------------------------------------------------------ structures

    def scrub_obj(self, obj: Any, _depth: int = 0) -> Any:
        """Copy of a JSON-like structure with strings scrubbed.

        Values under a sensitive key are replaced whole, whatever their
        type. Keys themselves are scrubbed too (people do put emails in map
        keys). Past ``max_depth`` the remainder is replaced, since an
        unbounded walk over attacker-shaped input is its own problem.
        """
        if _depth > self.max_depth:
            return "[TRUNCATED]"
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, Mapping):
            out: dict[Any, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and _norm_key(k) in self.sensitive_keys:
                    self.counts["sensitive_key"] += 1
                    out[k] = "[REDACTED]"
                else:
                    out[self.scrub(k) if isinstance(k, str) else k] = self.scrub_obj(v, _depth + 1)
            return out
        if isinstance(obj, list | tuple):
            items = [self.scrub_obj(v, _depth + 1) for v in obj]
            return items if isinstance(obj, list) else tuple(items)
        if isinstance(obj, bytes | bytearray):
            return self.scrub(bytes(obj).decode("utf-8", "replace")).encode()
        return obj


def _norm_key(k: str) -> str:
    return k.strip().lower().replace("-", "_")


def _partial(kind: str, norm: str) -> str:
    if kind == "card" or kind == "iban":
        return "..." + norm[-4:]
    if kind == "phone":
        return "..." + norm[-2:]
    if kind == "email":
        return "...@" + norm.rsplit("@", 1)[-1]
    return ""
