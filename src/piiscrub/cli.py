"""``piiscrub``: scrub text or JSON lines from stdin to stdout.

    piiscrub < app.log > app.scrubbed.log
    piiscrub --json --mode pseudonym < events.jsonl > events.out.jsonl

The pseudonym key is read from ``PIISCRUB_KEY`` (at least 16 bytes) so it
stays out of shell history and ``ps``. With ``--json`` each line is parsed
and walked with sensitive-key handling; lines that are not JSON are
scrubbed as text, so a mixed stream still comes out clean.

Counts by kind go to stderr with ``--stats``. Exit status is 0, or 2 for a
usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import TextIO

from piiscrub.detectors import DEFAULT_KINDS, KINDS
from piiscrub.scrubber import MODES, Scrubber

KEY_ENV = "PIISCRUB_KEY"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="piiscrub", description=__doc__.splitlines()[0])
    p.add_argument("--mode", choices=MODES, default="mask")
    p.add_argument(
        "--kinds",
        default=",".join(DEFAULT_KINDS),
        help=f"comma-separated, from: {', '.join(KINDS)} (default: all but ipv4)",
    )
    p.add_argument("--json", action="store_true", help="treat each line as a JSON document")
    p.add_argument("--stats", action="store_true", help="print counts by kind to stderr")
    return p


def run(args: argparse.Namespace, stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    key = os.environ.get(KEY_ENV)
    try:
        scrubber = Scrubber(
            [k.strip() for k in args.kinds.split(",") if k.strip()],
            mode=args.mode,
            key=key.encode() if key else None,
        )
    except ValueError as exc:
        hint = f" (set {KEY_ENV})" if args.mode == "pseudonym" else ""
        print(f"piiscrub: {exc}{hint}", file=stderr)
        return 2
    for line in stdin:
        body, nl = (line[:-1], "\n") if line.endswith("\n") else (line, "")
        if args.json:
            try:
                doc = json.loads(body)
            except ValueError:
                stdout.write(scrubber.scrub(body) + nl)
                continue
            out = json.dumps(scrubber.scrub_obj(doc), ensure_ascii=False, separators=(",", ":"))
            stdout.write(out + nl)
        else:
            stdout.write(scrubber.scrub(body) + nl)
    if args.stats:
        for kind, n in sorted(scrubber.counts.items()):
            print(f"{kind}\t{n}", file=stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args, sys.stdin, sys.stdout, sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
