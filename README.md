# secretmask

Typed, zero-dependency secret masker: redact API keys, tokens, emails and card
numbers in strings and nested data before they reach your logs.

## Install

```
pip install secretmask
```

## Usage

Mask a single string:

```python
from secretmask import mask_text

mask_text("Authorization: Bearer abc123def456ghi")
# 'Authorization: Bearer ***'

mask_text("contact jane.doe@example.com, card 4111 1111 1111 1111")
# 'contact ***, card ***'
```

Mask a whole structure before logging it. The value of any sensitive key is
hidden wholesale, string values are pattern-redacted, and lists and nested
mappings are walked for you. The input is never mutated:

```python
import logging
from secretmask import mask

payload = {
    "user": "ada",
    "password": "hunter2",
    "headers": {"Authorization": "Bearer eyJ..."},
    "note": "ping me at ada@example.com",
}

logging.info("request %s", mask(payload))
# {'user': 'ada', 'password': '***',
#  'headers': {'Authorization': '***'}, 'note': 'ping me at ***'}
```

Configure the placeholder, add your own patterns or key names, keep an allowlist,
or opt out of the built-ins. Build a `SecretMask` once and reuse it so the
patterns compile a single time:

```python
from secretmask import MaskConfig, SecretMask

config = MaskConfig(
    placeholder="[hidden]",
    extra_keys=("iban",),
    extra_patterns=(("ticket", r"TCK-\d{4}"),),
    allowlist=("support@lianes8studio.com",),  # never mask this one value
    label=True,  # show what was hidden: <redacted:email>
)
masker = SecretMask(config)
masker.mask_text("ref TCK-1234 for a@b.io")
# 'ref <redacted:ticket> for <redacted:email>'
```

### Strategies

Choose how a secret is rendered with `Strategy` (or the string form):

```python
from secretmask import MaskConfig, Strategy, mask_text

mask_text("Bearer abc123def456ghi", config=MaskConfig(strategy=Strategy.PARTIAL, keep_last=4))
# 'Bearer ***********6ghi'  (keep the tail so two tokens stay distinguishable)

mask_text("mail a@b.io", config=MaskConfig(strategy="hash"))
# 'mail <sha256:0f3306f4>'  (deterministic, correlatable, never readable)
```

- `full` replaces the secret with the placeholder (the default).
- `label` names the detector, for example `<redacted:jwt>`.
- `partial` keeps the last `keep_last` characters and masks the rest.
- `hash` replaces the secret with a short deterministic SHA-256 digest.

Masking is idempotent: masking an already-masked value changes nothing.

### JSON

```python
from secretmask import mask_json

mask_json('{"password": "p", "user": "ada", "note": "ping a@b.io"}')
# '{"password": "***", "user": "ada", "note": "ping ***"}'
```

### Command line

```
$ secretmask "Authorization: Bearer abc123def456ghi"
Authorization: Bearer ***

$ echo '{"password": "p", "user": "ada"}' | secretmask --json
{"password": "***", "user": "ada"}

$ secretmask --file app.log --strategy partial --keep-last 2
```

Run `secretmask --help` for every option. See [GUIDE.md](GUIDE.md) for a full
walk-through.

### What it detects out of the box

- JWTs and PEM private-key blocks
- `Bearer <token>` headers (the label is kept, the token goes)
- AWS access key ids, OpenAI, Stripe, GitHub, Slack and Google API keys
- Passwords inside URLs (`scheme://user:pass@host`) and connection strings
  (`Password=...;`), where only the password is hidden
- Generic `key = value` / `key: value` secret assignments in log lines
- Email addresses
- Credit-card numbers, validated with the Luhn checksum so ordinary 16-digit
  references are left alone
- The values of sensitive keys (`password`, `token`, `secret`, `authorization`,
  `api_key`, ...), matched case-insensitively and ignoring separators

## Why

`logging` in the standard library will happily write a bearer token or a
password straight to disk, and there is no built-in way to scrub it. The
maintained options do not quite fill the gap: `misprint` is typed and
dependency-free but only masks the exact strings or regexes you hand it, with no
built-in patterns and no recursive key masking; `loggingredactor` is tied to the
logging-filter machinery, matches keys case-sensitively, and ships no patterns
for JWTs, cloud keys or card numbers; `scrubadub` pulls in NLP dependencies for
PII detection, which is a different and much heavier job.

`secretmask` is the small piece in between: one typed, zero-dependency function
that both redacts a useful set of secret patterns in free text and recursively
masks the values of sensitive keys in nested data, so you can clean a payload in
one call before it is logged. It is a plain function, not a framework: no logging
handler to install, nothing to configure before it works, and no dependencies to
pull in. When you do want control, `MaskConfig` lets you add patterns and key
names or swap the placeholder without giving up the built-ins.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8/secretmask
- LinkedIn: https://www.linkedin.com/in/jlianes/
