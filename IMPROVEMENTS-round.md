# secretmask improvement round

Ranked, substantial improvements for this round. The library stays typed and
zero-dependency, the existing public API keeps working, and every change is
additive. Items are ordered by value to a user who wants to scrub secrets out of
logs and payloads safely.

## 1. Masking strategies beyond full replacement

Before this round the only choices were a fixed placeholder and a `label` flag.
Real redaction needs more:

- **full** - replace the secret with the placeholder (the default, unchanged).
- **label** - name the detector, for example `<redacted:jwt>` (the old `label`
  flag still works and maps to this).
- **partial** - keep the last N characters so a human can still tell two tokens
  apart in a log, for example `************ghi`. Never reveals the whole secret:
  a value no longer than `keep_last` is masked in full.
- **hash** - replace the secret with a short deterministic SHA-256 digest, for
  example `<sha256:ab12cd34>`, so the same secret is correlatable across lines
  without ever being readable.

A new `Strategy` enum (a `str` enum, so CLI and JSON pass it as plain text) plus
`keep_last` and `hash_length` fields on `MaskConfig`. The strategy applies to
both pattern matches and sensitive-key values.

## 2. More detectors for common secret shapes

Added to the built-in pattern set, ordered so a specific shape wins over a
generic one, and every regex linear (no nested quantifiers, no catastrophic
backtracking):

- **private_key** - PEM blocks (`-----BEGIN ... PRIVATE KEY----- ... -----END
  ... PRIVATE KEY-----`), RSA/EC/OPENSSH/PGP included.
- **url_credentials** - the password inside a URL userinfo
  (`scheme://user:PASSWORD@host`); only the password is hidden, the scheme, user
  and host survive.
- **connection_string** - `Password=...;` / `pwd=...` as used in ADO.NET and
  ODBC connection strings; only the value is hidden.
- **assignment** - a generic `key = value` / `key: value` secret in free text
  (`password`, `secret`, `token`, `api_key`, `access_token`, ...), which catches
  provider-less API keys and passwords dumped into a log line; only the value is
  hidden, the key name stays.

These join the existing JWT, AWS, OpenAI, Stripe, GitHub, Slack, Google, bearer,
email and Luhn-checked card detectors.

## 3. Allowlist

`MaskConfig.allowlist` is a tuple of exact strings that must never be masked
(public test fixtures, a well-known sample key, an email you want kept). Checked
for pattern matches, card matches and sensitive-key values alike.

## 4. Idempotence as a guaranteed, tested property

`mask(mask(x)) == mask(x)` for every strategy. The placeholders and digests are
chosen so re-masking an already-masked string changes nothing. A contract test
asserts it across strategies and inputs.

## 5. Unicode safety

Card and digit scanning is pinned to ASCII digits (`[0-9]`) so non-Latin digits
and scripts are never miscounted or corrupted, and masking round-trips arbitrary
Unicode text untouched. Covered by tests.

## 6. JSON helper

`mask_json(text)` parses a JSON document, masks it by structure (key names and
string values), and re-serializes it, so a caller with a JSON log line gets a
masked JSON line back in one call. Invalid JSON raises `ValueError`.

## 7. A command-line interface

`secretmask` console script (`[project.scripts]`, `argparse`):

- input from a positional string, `--file PATH`, or stdin;
- `--strategy`, `--placeholder`, `--keep-last`, `--hash-length`;
- `--pattern NAME=REGEX`, `--key NAME`, `--allow VALUE` (each repeatable);
- `--json` to mask a JSON document by structure;
- `--no-cards`, `--version`;
- a `--help` with runnable examples; errors go to stderr with exit code 1.

## 8. Documentation

A dedicated `GUIDE.md` walking through every detector, strategy, the allowlist,
the JSON helper and the CLI, plus expanded docstrings and an updated README and
changelog.

## 9. Real end-to-end coverage

A test that pip-installs the package editable and drives the real installed
`secretmask` console script through `subprocess` on real inputs, asserting the
real stdout and exit codes and that no secret leaks into the output.

## Out of scope on purpose

No network, no new dependencies, no entropy-based "maybe a secret" guessing
(too noisy for a library that must not corrupt good data), no logging handler to
install. The library stays a set of plain, predictable functions.
