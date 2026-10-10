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

Configure the placeholder, add your own patterns or key names, or opt out of the
built-ins. Build a `SecretMask` once and reuse it so the patterns compile a
single time:

```python
from secretmask import MaskConfig, SecretMask

config = MaskConfig(
    placeholder="[hidden]",
    extra_keys=("iban",),
    extra_patterns=(("ticket", r"TCK-\d{4}"),),
    label=True,  # show what was hidden: <redacted:email>
)
masker = SecretMask(config)
masker.mask_text("ref TCK-1234 for a@b.io")
# 'ref <redacted:ticket> for <redacted:email>'
```

### What it detects out of the box

- JWTs, `Bearer <token>` headers (the label is kept, the token goes)
- AWS access key ids, OpenAI, Stripe, GitHub, Slack and Google API keys
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
handler to install, nothing to configure before it works.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8/secretmask
- LinkedIn: https://www.linkedin.com/in/jlianes/
