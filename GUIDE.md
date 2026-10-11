# secretmask guide

A complete tour of `secretmask`: every detector, every strategy, the allowlist,
the JSON helper and the command-line interface. The library is typed and has no
runtime dependencies, and nothing here installs a logging handler or changes
global state. Every function returns a copy and never mutates its input.

## Two entry points

- `mask_text(text)` scans a single string for secret patterns and redacts them.
- `mask(value)` walks a value recursively: it pattern-redacts strings, hides the
  value of any sensitive key in a mapping, and walks lists, tuples and nested
  mappings. Non-string leaves (numbers, booleans, `None`) are returned as they
  are.

```python
from secretmask import mask, mask_text

mask_text("contact a@b.io, card 4111 1111 1111 1111")
# 'contact ***, card ***'

mask({"user": "ada", "password": "hunter2", "note": "ping a@b.io"})
# {'user': 'ada', 'password': '***', 'note': 'ping ***'}
```

## Detectors

Built-in patterns, tried in order so a specific shape wins over a generic one:

| Detector | Hides |
| --- | --- |
| `jwt` | `eyJ...` JSON web tokens |
| `private_key` | PEM `-----BEGIN ... PRIVATE KEY-----` blocks |
| `aws_key` | AWS access key ids (`AKIA...`) |
| `openai_key` | `sk-...` keys |
| `stripe_key` | `sk_live_...`, `rk_test_...` |
| `github_token` | `ghp_...`, `gho_...` and `github_pat_...` |
| `slack_token` | `xoxb-...` and friends |
| `google_api_key` | `AIza...` |
| `url_credentials` | the password in `scheme://user:pass@host` |
| `connection_string` | `Password=...;` / `pwd=...` values |
| `bearer` | the token after `Bearer` (the word is kept) |
| `assignment` | `password`/`secret`/`token`/`api_key` `= value` in logs |
| `email` | email addresses |
| credit cards | 13 to 19 digit runs that pass the Luhn checksum |

Sensitive keys are matched case-insensitively and ignoring separators, so
`API_Key`, `access-token` and `accessToken` all match. The value of a sensitive
key is hidden wholesale, even when it is a nested subtree.

Every regex is linear, with no nested quantifiers, so no input can trigger
catastrophic backtracking.

## Strategies

Set `strategy` on `MaskConfig` (an enum value or its string name).

```python
from secretmask import MaskConfig, Strategy, mask_text

mask_text("mail a@b.io", config=MaskConfig(strategy=Strategy.FULL))  # 'mail ***'
mask_text("mail a@b.io", config=MaskConfig(strategy=Strategy.LABEL))  # 'mail <redacted:email>'
mask_text("mail a@b.io", config=MaskConfig(strategy="partial", keep_last=3))  # 'mail ***.io'
mask_text("mail a@b.io", config=MaskConfig(strategy="hash"))  # 'mail <sha256:0f3306f4>'
```

- **full** replaces the secret with `placeholder` (default `***`).
- **label** names the detector that matched.
- **partial** keeps the last `keep_last` characters (default 4). A secret no
  longer than `keep_last` is masked in full, so nothing is ever revealed outright.
- **hash** replaces the secret with the first `hash_length` hex characters
  (default 8) of its SHA-256 digest, inside `<sha256:...>`. The same secret always
  hashes to the same token, so you can correlate occurrences across log lines
  without ever reading the value.

The strategy applies to pattern matches and to sensitive-key values alike. On a
non-string value (a masked subtree), `partial` and `hash` fall back to the
placeholder.

### Idempotence

`mask(mask(x)) == mask(x)` for every strategy. Re-masking a string that is
already masked changes nothing, including under `hash`, because a token the
library itself produced is recognised and left alone.

## Allowlist

`allowlist` holds exact strings that must never be masked, whether a pattern, the
card scanner or a sensitive key would otherwise hit them.

```python
from secretmask import MaskConfig, mask_text

mask_text("from noreply@site.com to a@b.io", config=MaskConfig(allowlist=("noreply@site.com",)))
# 'from noreply@site.com to ***'
```

## Custom patterns and keys

```python
from secretmask import MaskConfig, mask_text

config = MaskConfig(extra_patterns=(("ticket", r"TCK-\d{4}"),), extra_keys=("iban",))
mask_text("ref TCK-1234", config=config)  # 'ref ***'
```

A pattern is a `(name, regex)` pair. Expose a named group `s` to redact only part
of a match; without it the whole match is replaced. Set `use_builtin_patterns` or
`use_builtin_keys` to `False` to start from an empty set, and `mask_credit_cards`
to `False` to skip card scanning.

## JSON

`mask_json(text)` parses a JSON document, masks it by structure, and
re-serialises it. It raises `ValueError` on invalid JSON.

```python
from secretmask import mask_json

mask_json('{"password": "p", "token": "t", "user": "ada"}')
# '{"password": "***", "token": "***", "user": "ada"}'
```

## Command line

The `secretmask` console script reads from an argument, `--file`, or standard
input, and writes the masked result to standard output. Errors go to standard
error with exit code 1.

```
secretmask "Authorization: Bearer abc123def456ghi"
echo "pass password=hunter2" | secretmask --strategy partial --keep-last 2
secretmask --file app.log --strategy hash
secretmask --json '{"password": "p", "user": "ada"}'
secretmask --pattern "ticket=TCK-\d{4}" --allow a@b.io "ref TCK-1234 a@b.io"
```

Options: `--strategy`, `--placeholder`, `--keep-last`, `--hash-length`,
`--pattern NAME=REGEX`, `--key NAME`, `--allow VALUE` (each repeatable),
`--json`, `--no-cards`, `--version`. `python -m secretmask` works the same way.

## Reusing a masker

Build a `SecretMask` once and keep it: the patterns compile a single time, and
every call reuses them.

```python
from secretmask import MaskConfig, SecretMask

masker = SecretMask(MaskConfig(strategy="label"))
masker.mask_text("a@b.io")  # '<redacted:email>'
masker.mask({"token": "t"})  # {'token': '<redacted:token>'}
```
