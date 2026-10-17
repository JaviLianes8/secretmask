# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-16

The public API is now stable: `mask`, `mask_text`, `mask_json`, `SecretMask`,
`MaskConfig` and `Strategy`, with the signatures, defaults, detector names and output
forms documented in the guide, follow semantic versioning from here on.

### Added

- Detectors for Basic credentials (`basic_auth`), Slack webhook URLs
  (`slack_webhook`), Stripe webhook secrets and organization keys, Slack app-level,
  configuration and workflow tokens, GitHub's stateless `ghs_<app id>_<JWT>` tokens,
  OpenPGP private key blocks and unsecured or encrypted JWTs.
- `MaskConfig.hash_key`: a key for HMAC-SHA256 digests under the `hash` strategy.
- `SecretMask.config` and a `repr` for `SecretMask`.
- Every public name has examples that run as doctests; the guide documents every
  detector with the source of its format, the errors and the limits.
- Command line: `--file -` reads standard input.

### Changed (upgrading from 0.2.0)

- Detection follows each vendor's documented format and finds more:
  `AWS_SECRET_ACCESS_KEY=`, `client_secret=`, `dbPassword:`, `"password": "..."` in
  JSON-like text, `$config['api_key'] = '...'`, `key => value` and `key := value`,
  quoted values with spaces, values of any length (0.2.0 needed four characters),
  passwords in `redis://:pw@host` and passwords containing `@`. `password => x`
  is now hidden and `password=>x` keeps its `=>` (0.2.0 left the first in clear and
  gave `password=***` for the second).
- Fewer false hits: a token no longer starts inside a word (`risk-assessment-...`
  was read as an `sk-` key), only the AWS credential prefixes `AKIA`, `ASIA`, `ABIA`
  and `ACCA` are hidden (unique ids such as `AIDA...` stay), card digits must come
  in groups of three or more (`4 1 1 1 ...` stays), and a bare value ends at `&`, so
  the rest of a query string survives.
- A card followed by more digits, such as an expiry date or a year, is now found
  (0.2.0 counted the extra digits and missed the card). Grouped digits must follow a
  card layout, so a quantity written before a card is kept and the card found
  (0.2.0 missed the card in `qty 197 4242 4242 4242 4242`).
- A user name in a URL without a password is no longer read as an email address:
  0.2.0 turned `https://ada@example.org/x` into `https://***/x`.
- A private key block whose `END` line is missing is hidden instead of skipped.
- Sensitive keys must end a word: `author`, `authenticated`, `tokenizer` and
  `passwordless` are no longer hidden; `max_tokens` (a plural of `token`) now is.
- Overlapping matches become one redaction named after the earlier detector, and
  touching redactions are joined; masked output is stable when masked again, also
  with a custom placeholder such as `[hidden]` (0.2.0 turned it into `[hidden]]`).
- `MaskConfig` checks its arguments when it is built: wrong types raise `TypeError`,
  bad values `ValueError` (an invalid regex raised `re.error` in 0.2.0), a bare string
  where a tuple of strings is expected is refused, lists are stored as tuples, and
  pattern names are limited to 1 to 64 of `A-Z a-z 0-9 _ . -`. Error messages never
  repeat a long value.
- `mask_text` and `mask_json` raise `TypeError` for anything that is not a `str`, and
  `SecretMask` for a config that is not a `MaskConfig`.
- `mask` no longer recurses: any depth works, and a structure that contains itself
  raises `ValueError` instead of `RecursionError`. JSON nested too deeply for the
  parser raises `ValueError`.
- A match of zero characters from a custom pattern is ignored.
- Command line: a `--pattern` without `NAME=` and giving both text and `--file` are
  usage errors (exit status 2).
- Command line: text from a file or standard input is written back unchanged apart
  from the secrets (0.2.0 added a newline and failed on bytes that are not UTF-8),
  output is always UTF-8, an invalid `--pattern` regex is reported instead of a
  traceback, a closed pipe exits 0, Ctrl+C exits 130, and giving both text and
  `--file` is an error.
- The public classes and functions report `secretmask` as their module.

## [0.2.0] - 2026-10-11

### Added

- Masking strategies via the new `Strategy` enum and `strategy` on `MaskConfig`:
  `full` (placeholder), `label`, `partial` (keep the last `keep_last` characters)
  and `hash` (a short deterministic `<sha256:...>` digest of `hash_length` hex
  characters). The older `label=True` flag still works.
- More detectors: PEM private-key blocks, passwords inside URLs
  (`scheme://user:pass@host`), connection-string passwords (`Password=...;`) and
  generic `key = value` secret assignments in log lines.
- `allowlist` on `MaskConfig`: exact strings that are never masked.
- `mask_json`: mask a JSON document by structure and return masked JSON.
- A `secretmask` command-line interface (also runnable as `python -m secretmask`)
  with strategy, placeholder, pattern, key, allowlist, JSON and card options.
- A dedicated `GUIDE.md`.

### Changed

- Card scanning is pinned to ASCII digits so non-Latin numerals are never
  miscounted, and masking is guaranteed idempotent across every strategy.

## [0.1.0] - 2026-10-10

### Added

- `mask_text`: redact secret patterns in a string. Built-ins cover JWTs,
  `Bearer` tokens, AWS access key ids, OpenAI, Stripe, GitHub, Slack and Google
  API keys, email addresses, and credit-card numbers validated with the Luhn
  checksum.
- `mask`: redact a value recursively. Sensitive keys (`password`, `token`,
  `secret`, `authorization`, `api_key`, ...) are matched case-insensitively and
  ignoring separators, and their values are hidden wholesale; string values are
  pattern-redacted; lists and nested mappings are walked. The input is never
  mutated.
- `MaskConfig`: configure the placeholder, add patterns or key names, opt out of
  the built-ins, toggle credit-card masking, and label each redaction with what
  it hid.
- `SecretMask`: a reusable masker that compiles its patterns once.
- Full type hints with a shipped `py.typed` marker, and no runtime dependencies.
