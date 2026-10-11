# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
