# Security policy

## Reporting a problem

Please report security problems privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a value that gets through the scrubber, since the example is the exploit.

Include the input (with made-up values in the same shape), the configuration, the output, and the version or commit. You should get an acknowledgement within five working days. Fixes land on `main` with a regression test and a CHANGELOG entry that credits you unless you ask not to be named.

## Supported versions

This is a 0.x project. Only the latest commit on `main` gets fixes.

## In scope

- A value of a supported kind, in a shape the README says is covered, that comes out unredacted or partly redacted.
- A pseudonym that can be reversed or linked without the key.
- Input that makes scanning take time or memory far out of proportion to its length.
- The key showing up in `repr()`, exceptions or output.

## Out of scope

- Kinds of data the README lists as not detected (names, addresses, bare digit runs).
- Over-redaction: an id masked because it looks like a card. Open a normal issue.
