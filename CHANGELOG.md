# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

## [0.1.0] - 2026-11-14

First version.

- Detectors for email, phone (E.164 and North American), payment card (Luhn), US SSN (issuance rules), IBAN (per-country length and mod 97), JWT, `Bearer`/`Basic` credentials, URL passwords, secret-named fields, and opt-in IPv4.
- `mask`, `partial` and keyed `pseudonym` modes; credentials masked in all of them.
- `scrub_obj` for JSON-like structures, with whole-value replacement under sensitive keys and a depth limit.
- `ScrubFormatter` and `ScrubFilter` for `logging`, and a structlog processor.
- `piiscrub` command for text and JSON lines, with counts by kind.
