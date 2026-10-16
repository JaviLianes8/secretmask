"""Built-in secret detectors and the default sensitive key names.

Each detector is a ``(name, regex)`` pair. A regex may expose a named group ``s``
to redact only part of a match (the token after ``Bearer``, the password inside a
URL); without it the whole match is replaced. Formats follow each vendor's own
documentation; the facts and their sources are listed in GUIDE.md.
"""

from __future__ import annotations

# A token may not start in the middle of a longer word, so "risk-..." never reads
# as an "sk-" key and "disk_test_..." never as a Stripe key.
_START = r"(?<![A-Za-z0-9_-])"
_B64URL = r"[A-Za-z0-9_-]"

# Detectors run in this order and, where two matches overlap, the earlier one wins,
# so a known shape beats the generic "Bearer" and "key = value" rules. Every
# run that a required character follows is bounded, and a run is unbounded only where
# nothing has to follow it (so a secret of any length is hidden whole in one pass);
# matches only start where a token can start. The total work stays linear.
BUILTIN_PATTERNS: tuple[tuple[str, str], ...] = (
    # PEM (RFC 7468), OpenSSH and OpenPGP (RFC 4880) private keys. The body stops at
    # the next "-----", so a block whose END line was cut off is still hidden.
    (
        "private_key",
        r"-----BEGIN[ A-Z0-9_-]{0,64}?PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[^-]|-(?!----))*"
        r"(?:-----END[ A-Z0-9_-]{0,64}?PRIVATE KEY(?: BLOCK)?-----)?",
    ),
    # GitHub: classic, OAuth, app and refresh tokens, the stateless "ghs_APPID_JWT"
    # installation tokens, and fine-grained personal access tokens.
    (
        "github_token",
        _START + r"gh[pousr]_(?:[0-9]{1,20}_" + _B64URL + r"{2,}(?:\.[A-Za-z0-9_-]*){2}"
        r"|[A-Za-z0-9]{36,})",
    ),
    ("github_pat", _START + r"github_pat_[A-Za-z0-9_]{22,}"),
    # JSON Web Tokens (RFC 7519): a base64url JSON header, so always "eyJ", then two to
    # four more dot-separated segments (JWS, unsecured JWT, JWE).
    ("jwt", _START + r"eyJ" + _B64URL + r"{2,}(?:\.[A-Za-z0-9_-]*){2,4}"),
    # AWS access key ids: AKIA (long-term), ASIA (temporary), ABIA (STS service bearer
    # token), ACCA (context-specific credential). Other IAM unique ids are not secrets.
    ("aws_key", r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
    ("openai_key", _START + r"sk-[A-Za-z0-9_-]{20,}"),
    # Stripe secret, restricted and organization keys, and webhook signing secrets.
    # Publishable "pk_" keys are public by design and left alone.
    (
        "stripe_key",
        _START + r"(?:(?:sk|rk)_(?:live|test|org)_[A-Za-z0-9_]{10,}|whsec_[A-Za-z0-9+/=]{10,})",
    ),
    # Slack bot, user, workspace, refresh, configuration, app-level and workflow tokens.
    (
        "slack_token",
        r"(?<![A-Za-z0-9.-])(?:xoxe\.)?(?:xox[abeoprs]|xapp|xwfp)-[A-Za-z0-9-]{8,}",
    ),
    (
        "slack_webhook",
        r"hooks\.slack\.com/(?:services|workflows|triggers)/(?P<s>[A-Za-z0-9/_+-]{16,})",
    ),
    ("google_api_key", _START + r"AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    # The password in a URL's userinfo (RFC 3986 section 3.2.1); the user may be empty
    # ("redis://:pw@host") and up to three unescaped "@" in the password stay inside it.
    (
        "url_credentials",
        r"://[^:/?#@\s]{0,255}:(?P<s>[^\s/?#@]{1,255}(?:@[^\s/?#@]{1,255}){0,3})@",
    ),
    # ADO.NET and ODBC connection strings: quoted, braced or bare values.
    (
        "connection_string",
        r"(?i)(?<![A-Za-z0-9])(?:password|pwd)[ \t]{0,8}=(?!>)[ \t]{0,8}"
        r"(?P<s>\"[^\"\n]{0,1024}\"|'[^'\n]{0,1024}'|\{[^}\n]{0,1024}\}|[^;\s]+)",
    ),
    # HTTP authentication headers: Basic (RFC 7617) and Bearer (RFC 6750) credentials.
    (
        "basic_auth",
        r"(?i)\bauthorization[\"']?[ \t]{0,8}[:=][ \t]{0,8}[\"']?basic[ \t]{1,8}"
        r"(?P<s>[A-Za-z0-9+/]{4,}={0,2})",
    ),
    ("bearer", r"(?i)\bbearer[ \t]{1,8}(?P<s>[A-Za-z0-9._~+/=-]{8,})"),
    # "key = value" in logs, configs, env files, code and JSON-ish text, where the key
    # name holds a secret word ("dbPassword", "AWS_SECRET_ACCESS_KEY", "client_secret").
    # After the word only a separator or a capital may continue the name, so
    # "tokenizer" and "passwordless" are not keys. Quoted values may hold spaces.
    (
        "assignment",
        r"(?i)(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]{0,128}?"
        r"(?:passwords?|passwd|passphrase|pwd|secrets?|tokens?|credentials?"
        r"|(?:api|access|auth|private|secret|session|signing|encryption|master)[_-]?keys?"
        r"|(?:access|auth|refresh)[_-]?tokens?)"
        r"(?:(?:[_.-]|(?-i:[A-Z]))[A-Za-z0-9_.-]{0,32})?"
        r"[\"']?\]?[ \t]{0,8}(?:=>|:=|[:=])[ \t]{0,8}[\"']?"
        r"(?P<s>(?<=[\"'])[^\"'\n]{1,4096}(?=[\"'])|[^\s,;&'\"`)\]}]+)",
    ),
    ("email", r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}"),
)

# Default key names whose values are secrets wherever they appear in a mapping. Key
# names are compared lower-cased with separators removed, and a key matches when it
# contains one of these ("db_password", "X-Api-Key").
BUILTIN_KEYS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "secretkey",
    "sessionkey",
    "signingkey",
    "encryptionkey",
    "masterkey",
    "authorization",
    "auth",
    "credential",
    "sessionid",
    "cookie",
    "creditcard",
    "cardnumber",
    "cvv",
    "ssn",
)
