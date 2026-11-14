# pii-scrub

`piiscrub` takes personal data and credentials out of log lines and structured records before they leave the process: emails, phone numbers, payment card numbers, US Social Security numbers, IBANs, JWTs, `Authorization` header values, passwords in URLs, and any field named like a secret. Each match can be masked, partially kept, or replaced with a keyed pseudonym so the same customer can still be followed across log lines.

Standard library only. Python 3.11+.

Author: Art Akopian ([Banrox](https://banrox.com))

## Use it

```python
import logging
from piiscrub import Scrubber, ScrubFormatter

scrubber = Scrubber()  # mask mode, every detector except ipv4

handler = logging.StreamHandler()
handler.setFormatter(
    ScrubFormatter(scrubber, logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
)
logging.basicConfig(level=logging.INFO, handlers=[handler])

logging.info("signup %s from %s", "jane@example.com", "(415) 555-0134")
# 2026-11-14 09:12:03,114 INFO signup [EMAIL] from [PHONE]
```

Direct calls:

```python
>>> s = Scrubber(mode="partial")
>>> s.scrub("refund to 4111 1111 1111 1111 for jane@example.com")
'refund to [CARD ...1111] for [EMAIL ...@example.com]'

>>> s.scrub_obj({"user": "jane@example.com", "password": "hunter2", "headers": {"Authorization": "Bearer x"}})
{'user': '[EMAIL ...@example.com]', 'password': '[REDACTED]', 'headers': {'Authorization': '[REDACTED]'}}
```

From the shell, for files you need to hand to someone:

```sh
piiscrub < app.log > app.clean.log
PIISCRUB_KEY=... piiscrub --json --mode pseudonym --stats < events.jsonl > events.clean.jsonl
```

## What it finds

| Kind | Matches | Checked by |
| --- | --- | --- |
| `email` | `name@host.example` | no leading, trailing or doubled dots in the local part |
| `phone` | `+` and 8 to 15 digits, or North American numbers with separators: `(415) 555-0134`, `415.555.0134`, `1 415 555 0134` | digit count; area code and exchange start with 2 to 9 |
| `card` | 13 to 19 digits, optionally grouped with spaces or dashes | Luhn; first digit 2 to 6; one kind of separator |
| `ssn` | `ddd-dd-dddd` | not a number the SSA never issues (area 000, 666, 9xx; group 00; serial 0000) |
| `iban` | country code, check digits, 11 to 30 more, grouped or compact | length for the country; ISO 7064 mod 97 |
| `jwt` | `eyJ...eyJ...sig` | shape |
| `auth_header` | the credential after `Bearer` or `Basic` | has a digit, a symbol or mixed case (so "basic authentication" stays) |
| `url_password` | the password in `scheme://user:password@host` | |
| `secret_field` | the value in `password=...`, `api_key: ...`, `"client_secret": "..."`, `X-Api-Key: ...` and similar | not a placeholder (`null`, `${VAR}`, `{{var}}`, `<...>`) |
| `ipv4` | dotted quads, opt-in | octets 0 to 255, no leading zeros |

`scrub_obj` also replaces the whole value of any mapping key in `DEFAULT_SENSITIVE_KEYS` (`password`, `token`, `authorization`, `cookie`, `set-cookie`, `api_key` and others; case and `-`/`_` ignored), whatever its type. Pass `sensitive_keys=` to replace the set. Your own patterns go in through `extra=[Detector(...)]`.

## Modes

- `mask`: `[EMAIL]`, `[CARD]`. The default.
- `partial`: what support staff use to find a record, nothing that identifies a person alone: the last four of a card or IBAN, the last two of a phone number, the email domain.
- `pseudonym`: `[email:5d41402abc4b]`, the first 48 bits of HMAC-SHA256 over the kind and the normalised value. `Jane@Example.com` and `jane@example.com` give the same token, as do `(415) 555-0134` and `+14155550134`. A key of at least 16 bytes is required. An unkeyed hash of a phone number or SSN is not a pseudonym: the whole space is small enough to hash on a laptop in an afternoon, after which every token reads as the original. Rotate the key and old tokens stop matching new ones; that is the point of rotating it.

Credentials are always masked, in every mode. A pseudonym of a password would still show which accounts share one.

## Design notes

**Validators keep the noise down.** The patterns find candidates; checks that cost microseconds throw out the ones that only look right. Sixteen digits in a log line are usually an order id, and only those that start with 2 to 6 and pass Luhn are treated as cards. Luhn still passes one random number in ten, so some ids in that range get masked. That cost is accepted: over-redacting an id is cheap, leaking a card number is not.

**Credentials are matched first.** Detectors claim text in priority order: credentials, then email, then cards, IBANs, SSNs, then phone numbers. A lower-priority match that overlaps a claimed span is dropped whole rather than trimmed, so no fragment of it is left beside the replacement.

**Scrubbing repeats until nothing changes.** Removing one value can expose another: a phone number glued to a card fails its own boundary check until the card is replaced. `scrub` runs again on its output, at most four times. The Hypothesis suite checks that scrubbing twice gives the same result as scrubbing once, including on text assembled from values packed against each other.

**No regex that backtracks badly.** Every repeated part has an upper bound and no quantifier is nested inside another unbounded one. The test suite times the worst inputs we know of (100,000-character runs of digits, `@`, `password=` and so on), and all finish in well under a second.

**Use the formatter, not a logger filter.** `ScrubFormatter` scrubs the finished line, including tracebacks and fields from `extra` that your format string pulls in. `ScrubFilter` rewrites the record for handlers that ship records unformatted; it has to be on every such handler, because a filter on a logger does not run for records that propagate from child loggers, which is how most libraries log.

## Limitations

- Pattern matching finds values with a recognisable shape. Names, street addresses, dates of birth and free-text medical or financial details have none and are not detected. Keep them out of logs in the first place, or name the fields and use `sensitive_keys`.
- Numbers written without separators are only partly covered: a bare ten-digit string is not treated as a phone number, and nine digits are not treated as an SSN. Both match too many ids.
- An unquoted secret value ends at whitespace, `&`, `,`, `;`, `}` or `]`. A bare password containing one of those keeps its tail. Quoted values and `scrub_obj` do not have this problem.
- This reduces what ends up in logs. It does not make a system PCI DSS or GDPR compliant, and it is no substitute for not logging sensitive data in the first place.

## Benchmarks

Per-operation timings and how to reproduce them: [docs/benchmarks.md](docs/benchmarks.md).

## License

MIT. See [LICENSE](LICENSE). Copyright 2026 Banrox Inc.

Issues and patches are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately as described in [SECURITY.md](SECURITY.md). Changes are listed in [CHANGELOG.md](CHANGELOG.md).
