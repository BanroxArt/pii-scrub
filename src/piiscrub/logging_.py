"""Hooks for the standard ``logging`` module.

Two places to scrub, with different coverage:

``ScrubFormatter`` wraps the formatter on a handler and scrubs the finished
line: message, arguments, exception traceback, stack info and anything your
format string pulls from ``extra``. This is the one to use. It sees exactly
what is about to be written.

``ScrubFilter`` rewrites the record (message with arguments merged,
traceback text, stack info) before any handler formats it. Use it when
records leave the process unformatted, such as a queue handler or a handler
that ships ``record.__dict__`` as JSON. It does not see fields a formatter
adds later, and ``extra`` values are scrubbed only when they are strings,
mappings or lists.

Attach either to the handler, not the logger. A filter on a logger does not
run for records that propagate up from child loggers, which is how most
libraries log.
"""

from __future__ import annotations

import logging
from typing import Any

from piiscrub.scrubber import Scrubber

# Attributes every LogRecord has; anything else came in through ``extra``.
_RECORD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
}


class ScrubFormatter(logging.Formatter):
    def __init__(self, scrubber: Scrubber, inner: logging.Formatter | None = None) -> None:
        super().__init__()
        self.scrubber = scrubber
        self.inner = inner or logging.Formatter()

    def format(self, record: logging.LogRecord) -> str:
        return self.scrubber.scrub(self.inner.format(record))


class ScrubFilter(logging.Filter):
    def __init__(self, scrubber: Scrubber) -> None:
        super().__init__()
        self.scrubber = scrubber

    def filter(self, record: logging.LogRecord) -> bool:
        s = self.scrubber
        record.msg = s.scrub(record.getMessage())
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = s.scrub(record.exc_text)
            # Formatters fall back to exc_info only when exc_text is empty;
            # drop it anyway so a handler that re-renders cannot leak.
            record.exc_info = None
        if record.stack_info:
            record.stack_info = s.scrub(record.stack_info)
        for name, value in list(vars(record).items()):
            if name not in _RECORD_ATTRS and isinstance(value, str | dict | list | tuple):
                setattr(record, name, s.scrub_obj(value))
        return True


def structlog_processor(scrubber: Scrubber) -> Any:
    """A structlog processor; put it last before the renderer."""

    def process(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        out = scrubber.scrub_obj(event_dict)
        assert isinstance(out, dict)
        return out

    return process
