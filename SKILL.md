---
name: pii-scrub
description: Find and stop personal data and credentials leaking into application logs, error reports and exported records, using the piiscrub package from this repo. Use when the user asks to redact or mask PII in logs, clean a log file before sharing it, pseudonymise customer identifiers in analytics events, or audit a service for secrets in log output.
---

# Scrubbing logs and records

You are working in a codebase the user owns, or on log files they gave you.

## 1. Find where data leaves the process

- Logging setup: `logging.basicConfig`, `dictConfig`, handlers, structlog configuration. List every handler and where it writes.
- Other sinks: error trackers, analytics events, audit exports, request/response dumps in middleware, debug endpoints.
- Search the code for log calls that pass whole request bodies, headers, user objects or exceptions from HTTP clients (these often include the URL with credentials or the request headers).

## 2. Wire it in

- Standard logging: wrap each handler's formatter in `ScrubFormatter`. Only use `ScrubFilter` for handlers that send records unformatted, and put it on the handler, not the logger.
- structlog: add `structlog_processor(scrubber)` as the last step before the renderer.
- Structured exports: pass records through `scrubber.scrub_obj`. Add the project's own sensitive field names (`dob`, `national_id`, ...) to `sensitive_keys`.
- Choose the mode with the user: `mask` by default; `partial` where support needs to match records; `pseudonym` where analytics needs to follow one customer, with the key from the secret store, never hard-coded.

## 3. Check it

- Add a test that logs a line with a made-up email, phone, card (4111 1111 1111 1111) and `password=...`, and asserts none of them reach the handler output.
- Run the app's test suite with the scrubber on and grep the captured logs for `@` and long digit runs.
- For an existing log file: `piiscrub --stats < file > /dev/null` shows what kinds it contains and how many, without printing them.

## 4. Report

List the sinks covered and not covered, the mode chosen, and the data the detectors cannot see (names, addresses, free text). For those, point at the log calls that should stop including them; that fix belongs in the code, not in the scrubber.

Never paste real log lines containing personal data into an issue, commit or chat while doing this. Show counts and redacted output.
