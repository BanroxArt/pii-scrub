"""Micro-benchmarks. Run: PYTHONPATH=src python bench/run.py

Standard library timeit, best of five repeats. Numbers are per operation on
one CPU core; compare runs on the same machine, not across machines.
"""

from __future__ import annotations

import platform
import sys
import timeit
from collections.abc import Callable

from piiscrub import Scrubber


def bench(name: str, fn: Callable[[], object], number: int, repeat: int = 5) -> None:
    best = min(timeit.repeat(fn, number=number, repeat=repeat)) / number
    print(f"| {name} | {best * 1e6:,.2f} | {1 / best:,.0f} |")


def header() -> None:
    print(f"Python {platform.python_version()} on {platform.machine()} ({sys.platform})\n")
    print("| case | µs/op | ops/s |")
    print("|---|---:|---:|")


CLEAN = "GET /health 200 3ms worker=4 region=eu-west-1 cache=hit " * 3
DIRTY = (
    "user jane.doe@example.com paid with 4111 1111 1111 1111 from (415) 555-0134, "
    "ssn 219-09-9999, iban GB82 WEST 1234 5698 7654 32"
)
RECORD = {
    "user": {"email": "jane@example.com", "phone": "+1 415 555 0134"},
    "password": "hunter2-not-real",
    "events": [{"note": DIRTY}, {"note": CLEAN}] * 5,
}


def main() -> None:
    header()
    mask = Scrubber()
    pseudo = Scrubber(mode="pseudonym", key=b"k" * 32)
    bench(f"mask, clean line ({len(CLEAN)} chars)", lambda: mask.scrub(CLEAN), 20000)
    bench(f"mask, line with 5 findings ({len(DIRTY)} chars)", lambda: mask.scrub(DIRTY), 20000)
    bench("pseudonym (HMAC), line with 5 findings", lambda: pseudo.scrub(DIRTY), 20000)
    bench("scrub_obj, nested record (12 strings)", lambda: mask.scrub_obj(RECORD), 5000)
    big = "\n".join([CLEAN, DIRTY] * 500)
    bench(f"mask, 1,000-line blob ({len(big):,} chars)", lambda: mask.scrub(big), 20)


if __name__ == "__main__":
    main()
