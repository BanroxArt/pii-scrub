from __future__ import annotations

import io
import logging
from collections.abc import Iterator

import pytest

from piiscrub import Scrubber, ScrubFilter, ScrubFormatter
from piiscrub.logging_ import structlog_processor


@pytest.fixture
def logger() -> Iterator[tuple[logging.Logger, io.StringIO, logging.Handler]]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    log = logging.getLogger("piiscrub.test")
    log.handlers = [handler]
    log.propagate = False
    log.setLevel(logging.INFO)
    yield log, stream, handler
    log.handlers = []


def test_formatter_scrubs_message_args_and_traceback(
    logger: tuple[logging.Logger, io.StringIO, logging.Handler],
) -> None:
    log, stream, handler = logger
    handler.setFormatter(ScrubFormatter(Scrubber(), logging.Formatter("%(levelname)s %(message)s")))
    log.info("signup %s", "jane@example.com")
    try:
        raise ValueError("bad card 4111111111111111")
    except ValueError:
        log.exception("failed for %s", "a@example.com")
    out = stream.getvalue()
    assert "example.com" not in out and "4111" not in out
    assert "INFO signup [EMAIL]" in out
    assert "ValueError: bad card [CARD]" in out


def test_formatter_covers_extra_fields_in_format(
    logger: tuple[logging.Logger, io.StringIO, logging.Handler],
) -> None:
    log, stream, handler = logger
    handler.setFormatter(ScrubFormatter(Scrubber(), logging.Formatter("%(user)s %(message)s")))
    log.info("hello", extra={"user": "jane@example.com"})
    assert stream.getvalue() == "[EMAIL] hello\n"


def test_filter_rewrites_record(
    logger: tuple[logging.Logger, io.StringIO, logging.Handler],
) -> None:
    log, _, _ = logger
    seen: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record)

    cap = Capture()
    cap.addFilter(ScrubFilter(Scrubber()))
    log.addHandler(cap)
    try:
        raise RuntimeError("password=hunter2")
    except RuntimeError:
        log.error(
            "call %s",
            "(415) 555-0134",
            extra={"ctx": {"email": "a@example.com", "token": "t"}, "n": 3},
            stack_info=True,
            exc_info=True,
        )
    rec = seen[0]
    assert rec.getMessage() == "call [PHONE]"
    assert rec.args is None
    assert rec.exc_info is None
    assert rec.exc_text is not None and "password=[REDACTED]" in rec.exc_text
    assert rec.ctx == {"email": "[EMAIL]", "token": "[REDACTED]"}  # type: ignore[attr-defined]
    assert rec.n == 3  # type: ignore[attr-defined]


def test_structlog_processor() -> None:
    proc = structlog_processor(Scrubber())
    event = {"event": "login a@example.com", "password": "x", "attempt": 2}
    assert proc(None, "info", event) == {
        "event": "login [EMAIL]",
        "password": "[REDACTED]",
        "attempt": 2,
    }
