"""Built-in secret patterns and the credit-card scanner.

Each pattern is a ``(name, regex)`` pair. A regex may expose a named group ``s``
to redact only part of a match (for example the token after ``Bearer``); without
it the whole match is replaced.
"""

from __future__ import annotations

# Order matters: structured tokens (JWT, provider keys) are tried before the
# looser "Bearer <token>" rule so a known shape wins over the generic one.
BUILTIN_PATTERNS: tuple[tuple[str, str], ...] = (
    ("jwt", r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
    ("aws_key", r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}"),
    ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    ("stripe_key", r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("github_pat", r"github_pat_[A-Za-z0-9_]{22,}"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
    ("bearer", r"(?i)\bbearer\s+(?P<s>[A-Za-z0-9._~+/=-]{8,})"),
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
)

# Default key names whose values are secrets wherever they appear in a mapping.
BUILTIN_KEYS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "accesstoken",
    "refreshtoken",
    "authorization",
    "auth",
    "privatekey",
    "clientsecret",
    "sessionid",
    "cookie",
    "creditcard",
    "cardnumber",
    "cvv",
    "ssn",
)

# A card is 13 to 19 digits, optionally grouped by single spaces or hyphens, not
# glued to other digits. Candidates are Luhn-checked before being redacted.
_CARD_CANDIDATE = r"(?<![\d-])(?:\d[ -]?){13,19}(?<=\d)"


def luhn_ok(digits: str) -> bool:
    """Return True if a run of digits passes the Luhn checksum."""
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0
