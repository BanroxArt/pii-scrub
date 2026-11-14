# Contributing

Bug reports and patches are welcome. For a new detector or anything larger than a small fix, open an issue first so we can agree on the shape and on how it will be validated.

## Setup

```sh
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

`make check` runs ruff (lint and format), the content lint in `scripts/check.py`, mypy in strict mode over `src/`, and pytest including the Hypothesis property tests. CI runs the same steps on Python 3.11 to 3.13.

## Adding a detector

- Give it a validator. A pattern alone matches too much; say in the pull request what the check is and roughly what fraction of random input of the right shape still passes it.
- Bound every repetition and add the worst input you can think of to `test_hostile_input_is_linear_enough`.
- Add it to the Hypothesis generators in `tests/test_properties.py` so idempotence and planted-value removal cover it.
- Pick a priority relative to the existing detectors and add a test for the overlap you expect.

## Things we will not merge

- Real personal data or credentials in tests, fixtures or issues, even ones that look expired. Use RFC 2606 domains (`example.com`), the NANP 555-01xx range, the card networks' published test numbers, and IBANs from the registry's documentation examples. `scripts/check.py` enforces most of this.
- Unkeyed hashing as a pseudonym mode.
- Runtime dependencies.

## Commit messages

Short imperative subject in lower case (`detectors: accept dotted NANP numbers`), a blank line, then why. Sign-off is not required.

## Conduct

Everyone taking part in issues, pull requests and reviews is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). Reports go to opensource@banrox.com and are read by the maintainers only.
