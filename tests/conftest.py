from __future__ import annotations

import base64
import json

from hypothesis import settings

settings.register_profile("default", deadline=None, max_examples=200)
settings.load_profile("default")

KEY = b"0123456789abcdef-test-only"


def b64url(obj: object) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt() -> str:
    # Built at runtime so no token-shaped literal sits in the repo.
    head = b64url({"alg": "HS256", "typ": "JWT"})
    body = b64url({"sub": "user-1", "exp": 1})
    return f"{head}.{body}.{'x' * 43}"


def luhn_complete(prefix: str) -> str:
    """Append the check digit that makes prefix + digit pass Luhn."""
    for d in "0123456789":
        candidate = prefix + d
        total = 0
        for i, ch in enumerate(reversed(candidate)):
            n = int(ch) * (2 if i % 2 else 1)
            total += n - 9 if n > 9 else n
        if total % 10 == 0:
            return candidate
    raise AssertionError("unreachable")
