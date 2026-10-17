# secretmask guide

Everything `secretmask` does: the detectors and where their formats come from, the
strategies, sensitive keys, the allowlist, JSON, the command line, errors and limits.
The library is typed, has no runtime dependencies, keeps no global state and installs
no logging handler. Every function returns a copy and never changes its input.

## The six public names

| Name | What it does |
| --- | --- |
| `mask_text(text, *, config=None)` | scan one string, return it masked |
| `mask(value, *, config=None)` | mask nested data: dicts, lists, tuples, strings |
| `mask_json(text, *, config=None)` | parse JSON, mask it by structure, serialise it again |
| `SecretMask(config=None)` | a reusable masker with the same three methods and `.config` |
| `MaskConfig(...)` | the configuration, a frozen dataclass |
| `Strategy` | how a secret is shown: `FULL`, `LABEL`, `PARTIAL`, `HASH` |

```python
from secretmask import mask, mask_json, mask_text

print(mask_text("contact ada@example.com, card 4242 4242 4242 4242"))
# contact ***, card ***
print(mask({"user": "ada", "password": "hunter2", "tags": ("a@b.io", 1)}))
# {'user': 'ada', 'password': '***', 'tags': ('***', 1)}
print(mask_json('{"token": "t", "user": "ada"}'))
# {"token": "***", "user": "ada"}
```

## Detectors

Detectors run in this order; when two find overlapping text, the two matches become
one redaction named after the earlier detector, so a known shape wins over a generic
one (`Bearer <jwt>` reads `Bearer <redacted:jwt>`). Redactions that touch are joined.

| Detector | Hides | Format source |
| --- | --- | --- |
| `private_key` | PEM, OpenSSH and OpenPGP private key blocks, whole | RFC 7468, RFC 4880 |
| `github_token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens, also `ghs_<app id>_<JWT>` | GitHub docs, token formats |
| `github_pat` | `github_pat_` fine-grained tokens | GitHub docs |
| `jwt` | `eyJ...` JSON web tokens, signed, unsecured or encrypted | RFC 7519 |
| `aws_key` | access key ids `AKIA`, `ASIA`, `ABIA`, `ACCA` + 16 characters | AWS IAM identifiers |
| `openai_key` | `sk-` keys of 20 or more characters | gitleaks and trufflehog rules |
| `stripe_key` | `sk_` and `rk_` keys (`live`, `test`, `org`), `whsec_` secrets | Stripe docs, API keys |
| `slack_token` | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxe-`, `xapp-`, `xwfp-` | Slack docs, gitleaks rules |
| `slack_webhook` | the path of a `hooks.slack.com` webhook URL | gitleaks and trufflehog rules |
| `google_api_key` | `AIza` + 35 characters | Google Cloud docs, API keys |
| `url_credentials` | the password in `scheme://user:password@host` | RFC 3986, 3.2.1 |
| `connection_string` | `Password=` and `Pwd=` values, bare, quoted or in braces | |
| `basic_auth` | the credentials after `Authorization: Basic` | RFC 7617 |
| `bearer` | the token after `Bearer` (8 or more characters) | RFC 6750 |
| `assignment` | the value in `key = value`, `key: value`, `"key": "value"`, `key => value` | |
| `email` | email addresses | |
| `credit_card` | 13 to 19 digits that pass the Luhn checksum | Stripe test card numbers |

The sources are fetched by `scripts/fetch_sources.py` (URLs, dates and hashes in
`tests/sources/MANIFEST.json`) and read by the tests, which also check that whatever
gitleaks, trufflehog and detect-secrets report in a synthetic corpus is hidden.

Notes on the edges:

- A token does not start inside a longer word: `risk-assessment-...` is not an `sk-`
  key and `disk_test_...` is not a Stripe key, while `x-ghp_...` and `tok_sk-...` are
  found. A Google key must end there (`AIza` + 35 characters + `_prod` is a longer
  name, as gitleaks reads it too). Stripe publishable keys (`pk_`) are
  public by design and stay. Of the twelve AWS unique id prefixes only the four
  credential ones are hidden; `AIDA...` (a user id) and `AROA...` (a role id) stay.
- A private key block whose `END` line was cut off is hidden up to the next `-----`
  or the end of the text: a truncated key is still a key.
- `assignment` reads the key as a whole name that contains a secret word (`password`,
  `passwd`, `passphrase`, `pwd`, `secret`, `token`, `credential`, an `api`, `access`,
  `auth`, `private`, `secret`, `session`, `signing`, `encryption` or `master` key, an
  `access`, `auth` or `refresh` token, plurals included), so `AWS_SECRET_ACCESS_KEY=`,
  `dbPassword:` and `$config['api_key'] =` are found while `tokenizer=` and
  `passwordless=` are not. A quoted value runs to its closing quote and may hold
  spaces, the other quote and backslash escapes; a bare value ends at whitespace or
  one of `` , ; & ' " ` ) ] } ``, so the next parameter of a query string survives.
- A connection-string value may also be doubled-quote escaped (`"pa""ss"`), braced
  (`{pa}}ss}`) or contain spaces when a `;` ends it (`Password=my secret 99;`).
- An email address never starts inside a URL's authority, so
  `postgres://app:pw@db.example.com` keeps its host and `https://ada@example.org`
  stays; after `mailto:` it is found.
- A card is an unbroken run of 13 to 19 digits, or digit groups joined by single
  spaces or hyphens in a card layout: a first group of four, middle groups of four
  or six, a last group of at most six (4-4-4-4, 4-6-5, 4-6-4, 4-4-4-2). So
  `4242 4242 4242 4242 12/26` keeps the date and `qty 197 4242 ...` the quantity.
  When a run can be read as two overlapping cards (a four-digit number right before
  one), both readings are hidden. Only ASCII digits count.

## Strategies

```python
from secretmask import MaskConfig, Strategy, mask_text

print(mask_text("mail a@b.io", config=MaskConfig(strategy=Strategy.FULL)))  # mail ***
print(mask_text("mail a@b.io", config=MaskConfig(strategy="label")))  # mail <redacted:email>
print(mask_text("mail a@b.io", config=MaskConfig(strategy="partial", keep_last=3)))
# mail ***.io
print(mask_text("mail a@b.io", config=MaskConfig(strategy="hash")))  # mail <sha256:0f3306f4>
```

- **full** (default) shows `placeholder` (default `***`).
- **label** shows `<redacted:NAME>`, the detector or, for a sensitive key, the key.
- **partial** keeps the last `keep_last` characters (default 4) and stars the rest. A
  secret no longer than `keep_last`, or any secret when `keep_last` is 0, gets the
  placeholder, so nothing is ever shown whole.
- **hash** shows `<sha256:...>` with the first `hash_length` hex characters (1 to 64,
  default 8) of the SHA-256 digest, so equal secrets can be matched across lines. A
  digest of a short or guessable secret can be reversed by trying candidates; set
  `hash_key` (a `str` or `bytes`) to use a keyed HMAC-SHA256 instead. `hash_key` is
  left out of the config's `repr`.

`label=True` is the older spelling of `strategy="label"`; an explicit `strategy` wins.
On a value that is not a string (a number, a nested dict under a sensitive key),
`partial` and `hash` fall back to the placeholder.

### Masking twice changes nothing

`mask_text(mask_text(x)) == mask_text(x)` and `mask(mask(x)) == mask(x)` for the
built-in detectors and every strategy: placeholders, labels and digests the library
made are recognised and left as they are. A replacement can make the surrounding text
match something new (a quoted value whose line break was inside a key block), so a
scan repeats until it finds nothing new; real text settles after one pass. Custom
patterns that match the placeholder can break this.

## Sensitive keys

In a mapping, the value of a sensitive key is replaced whole, whatever its type, and is
not walked. A key is split into words (`accessToken`, `ACCESS_TOKEN`, `access-token`
all give `access token`) and is sensitive when one of the names, joined across words
if needed, ends a word, optionally followed by a plural `s`: `db_password`,
`mypassword`, `oauth` (ends in `auth`) and `apiKeys` match. Built in: `password`, `passwd`, `passphrase`, `pwd`,
`secret`, `token`, `apikey`, `accesskey`, `privatekey`, `secretkey`, `sessionkey`,
`signingkey`, `encryptionkey`, `masterkey`, `authorization`, `auth`, `credential`,
`sessionid`, `cookie`, `creditcard`, `cardnumber`, `cvv`, `ssn`. So `X-Api-Key`,
`API_KEYS` and `cvv2` match; `author`, `tokenizer` and `passwordless` do not. Keys that are not strings are never sensitive.

```python
from secretmask import MaskConfig, mask

config = MaskConfig(extra_keys=("iban",))
print(mask({"payee_IBAN": "ES00", "auth": {"user": "ada"}, 1: "a@b.io"}, config=config))
# {'payee_IBAN': '***', 'auth': '***', 1: '***'}
```

Mappings come back as `dict`, lists as `list`, tuples (named tuples too) as plain
`tuple`; sets, bytes and other objects are returned as they are. Depth is limited only
by memory. A structure that contains itself raises `ValueError`.

## Allowlist, custom detectors, switches

```python
from secretmask import MaskConfig, mask_text

config = MaskConfig(
    allowlist=("noreply@example.com",),
    extra_patterns=(("ticket", r"TCK-\d{4}"), ("pin", r"PIN (?P<s>\d{4})")),
)
print(mask_text("from noreply@example.com to a@b.io, TCK-1234, PIN 0042", config=config))
# from noreply@example.com to ***, ***, PIN ***
```

- `allowlist`: exact values never masked, whether a detector, the card scanner or a
  sensitive key finds them.
- `extra_patterns`: `(name, regex)` pairs tried after the built-ins. A named group `s`
  hides only that part. Names are 1 to 64 of `A-Z a-z 0-9 _ . -`. A match of zero
  characters is ignored.
- `extra_keys`: more sensitive key names, with the same word rule. Key names apply to
  mappings (and so to `mask_json` and `--json`); free text is read by the detectors
  only, so add an `extra_patterns` entry for `iban=...` in plain text.
- `use_builtin_patterns=False`, `use_builtin_keys=False`, `mask_credit_cards=False`
  switch the built-ins off.

Lists are accepted wherever a tuple is expected. A config is frozen, hashable,
comparable and picklable; build a `SecretMask` once and reuse it. A masker keeps no
state that changes its results, so threads can share it.

## Errors

| Error | When |
| --- | --- |
| `TypeError` | a config field of the wrong type (a `str` where a tuple of strings is expected, a `bool` for `keep_last`), `SecretMask` given something that is not a `MaskConfig`, `mask_text` or `mask_json` given something that is not a `str` |
| `ValueError` | `keep_last` below 0, `hash_length` outside 1 to 64, an unknown strategy, a bad pattern name, an invalid regex, invalid JSON, JSON nested deeper than the parser allows, a structure that contains itself |

The library's own messages never repeat a long value: a value longer than 24
characters is described by its length only, so a secret pasted into the wrong field
does not end up in a log. Invalid JSON raises `json.JSONDecodeError` (a `ValueError`),
whose message gives only the position but whose `doc` attribute holds the document.
On the command line, argparse quotes an invalid `--strategy` choice or number as given.

## Command line

`secretmask` (or `python -m secretmask`) masks an argument, a file (`--file PATH`,
`-` for standard input) or standard input, and writes UTF-8 to standard output.

```
secretmask "Authorization: Bearer abc123def456ghi"
secretmask --file app.log --strategy partial --keep-last 2 > app.masked.log
cat app.log | secretmask --strategy hash --hash-length 12
secretmask --json '{"password": "p", "user": "ada"}'
secretmask --pattern "ticket=TCK-[0-9]{4}" --allow a@b.io "TCK-1234 a@b.io"
secretmask --json --key iban '{"iban": "ES00", "user": "ada"}'
```

Options: `--strategy`, `--placeholder`, `--keep-last`, `--hash-length`, `--pattern
NAME=REGEX`, `--key NAME`, `--allow VALUE` (the last three repeatable), `--json`,
`--no-cards`, `--version`, `--help`.

- Text from a file or standard input is written back byte for byte except for the
  secrets: line endings stay, nothing is added, and bytes that are not valid UTF-8
  pass through unchanged. A positional argument gets a newline; `--json` output is the
  JSON on one line and a newline.
- Exit status: 0 on success (also when the reader closes the pipe early), 1 for an
  error (message on standard error, starting with `secretmask:`; a bad value such as
  `--keep-last -1`, an invalid regex, a missing file, invalid JSON), 2 for bad usage
  (an unknown option or choice, a `--pattern` without `NAME=`, text and `--file`
  together), 130 on Ctrl+C.
- The whole input is read before it is masked, so a key block split across lines is
  still found.

## What it does not do

It does not guess secrets from randomness (entropy): that flags hashes, ids and
base64 data and would corrupt good logs. It does not read XML elements
(`<password>x</password>`), command-line flags (`--password x`) or bytes. Anything a
built-in misses can be added with `extra_patterns` and `extra_keys`.

## Upgrading from 0.2.0

See the [CHANGELOG](https://github.com/JaviLianes8/secretmask/blob/main/CHANGELOG.md)
for every difference. Code written for 0.2.0 keeps working: names, signatures and
defaults are the same, with stricter checks on wrong arguments.
