# secretmask

[![Lianes8 Certified](https://lianes8studio.com/certified/lianes8-certified-badge.svg)](https://lianes8studio.com/certified)

Typed, zero-dependency secret masker: redact API keys, tokens, passwords, emails and
card numbers in strings, logs, JSON and nested data before they are stored.

```
pip install secretmask
```

Python 3.10 or later. No runtime dependencies. Full guide:
[GUIDE.md](https://github.com/JaviLianes8/secretmask/blob/main/GUIDE.md) · changes:
[CHANGELOG.md](https://github.com/JaviLianes8/secretmask/blob/main/CHANGELOG.md).

## The problem

A log line, an error report or a debug dump is the easiest place for a credential to
leak: `logging` writes whatever it is given, and a request payload or an exception
message often carries an `Authorization` header, a database URL with its password, or
a cloud key. `secretmask` cleans the text or the data before it leaves your process.

## Quick start

```python
from secretmask import mask, mask_text

print(mask_text("Authorization: Bearer abc123def456ghi"))
# Authorization: Bearer ***

print(mask_text("db=postgres://app:s3cr3t@db:5432/main card 4242 4242 4242 4242"))
# db=postgres://app:***@db:5432/main card ***

payload = {"user": "ada", "db_password": "hunter2", "note": "mail ada@example.com"}
print(mask(payload))
# {'user': 'ada', 'db_password': '***', 'note': 'mail ***'}
```

`mask` walks dicts, lists and tuples: the value of a sensitive key (`password`,
`apiKey`, `X-Api-Key`, `client_secret`, ...) is hidden whole, every other string is
scanned. The input is never changed.

Choose how secrets are shown, add your own detectors, keep known values:

```python
from secretmask import MaskConfig, SecretMask

masker = SecretMask(
    MaskConfig(
        strategy="label",  # or "full", "partial", "hash"
        extra_patterns=(("ticket", r"TCK-\d{4}"),),
        allowlist=("support@example.com",),
    )
)
print(masker.mask_text("TCK-1234 from ada@example.com, cc support@example.com"))
# <redacted:ticket> from <redacted:email>, cc support@example.com
```

From the shell, on a file, standard input or JSON:

```
$ secretmask "token=abc123"
token=***
$ secretmask --strategy hash < app.log > app.masked.log
$ echo '{"password": "p", "user": "ada"}' | secretmask --json
{"password": "***", "user": "ada"}
```

## What it finds

Vendor formats as each vendor documents them: AWS access key ids (`AKIA`, `ASIA`,
`ABIA`, `ACCA`), GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`,
`github_pat_`), Stripe secret, restricted and webhook keys, Slack tokens and webhook
URLs, Google API keys, OpenAI-style `sk-` keys, JWTs, and PEM, OpenSSH and OpenPGP
private keys. Generic shapes: passwords in URLs and connection strings, `Basic` and
`Bearer` credentials, `key = value` assignments whose key names a secret, email
addresses, and card numbers that pass the Luhn checksum. The
[guide](https://github.com/JaviLianes8/secretmask/blob/main/GUIDE.md#detectors) lists
every detector with its source.

The detectors are checked against the vendors' own documentation and RFC examples,
and against the rule sets of gitleaks, trufflehog and detect-secrets: whatever those
tools call a secret in the test corpus is hidden.

## Why another one

- `scrubadub` finds personal data with natural-language tooling and depends on
  `textblob`, `scikit-learn` and six other packages; it is not aimed at credentials.
- `loggingredactor` and `misprint` are logging filters: they redact records as they
  pass through `logging`, not a string or a payload you hold.
- `detect-secrets`, `gitleaks` and `trufflehog` scan repositories and files and report
  findings; they do not hand back a cleaned copy of a string.

`secretmask` is a plain function you can call anywhere (a log formatter, an error
handler, an API response, a CLI pipe) that already knows the common credential formats,
masks nested data by key, and depends on nothing.

## License

MIT. See [LICENSE](https://github.com/JaviLianes8/secretmask/blob/main/LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8/secretmask
- LinkedIn: https://www.linkedin.com/in/jlianes/
