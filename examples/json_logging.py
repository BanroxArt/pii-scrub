"""Logging setup for a typical web service: JSON lines, scrubbed.

Runs with the standard library only; the same handler setup works under any
framework that uses ``logging``.

    python examples/json_logging.py
"""

from __future__ import annotations

import json
import logging
import os

from piiscrub import Scrubber, ScrubFormatter


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {"level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc)


def configure() -> None:
    key = os.environ.get("PIISCRUB_KEY")
    scrubber = Scrubber(mode="pseudonym", key=key.encode()) if key else Scrubber()
    handler = logging.StreamHandler()
    handler.setFormatter(ScrubFormatter(scrubber, JsonFormatter()))
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


if __name__ == "__main__":
    configure()
    log = logging.getLogger("checkout")
    log.info("payment failed for %s card %s", "jane@example.com", "4111 1111 1111 1111")
    try:
        raise ConnectionError("POST https://svc:hunter2@payments.example.com/charge timed out")
    except ConnectionError:
        log.exception("upstream error")
