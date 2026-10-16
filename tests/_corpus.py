"""Synthetic, seeded fake secrets in each vendor's documented format.

Nothing here is a real credential, and no token appears literally in the source:
each one is assembled at run time from a seeded generator and carries a marker a
real one never has (AWS's own "EXAMPLE" suffix, "FAKE", a broken GitHub checksum,
an unsigned JWT), so the repository never holds anything that looks live.
"""

from __future__ import annotations

import base64
import json
import random
import string

ALNUM = string.ascii_letters + string.digits
B32 = string.ascii_uppercase + "234567"
B64URL = ALNUM + "-_"


def _pick(rng: random.Random, alphabet: str, size: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(size))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt(rng: random.Random) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": _pick(rng, ALNUM, 8), "fake": True}).encode())
    return f"{header}.{payload}.{_pick(rng, B64URL, 43)}"


def card(rng: random.Random, prefix: str = "4", length: int = 16) -> str:
    body = prefix + "".join(rng.choice(string.digits) for _ in range(length - len(prefix) - 1))
    for check in string.digits:
        digits = body + check
        total = sum(int(d) for d in digits[-1::-2])
        total += sum(int(c) for d in digits[-2::-2] for c in str(int(d) * 2))
        if total % 10 == 0:
            return digits
    raise AssertionError("unreachable")


def pem(rng: random.Random, label: str) -> str:
    lines = [_pick(rng, ALNUM + "+/", 64) for _ in range(4)]
    body = "\n".join(lines)
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----"


def tokens(seed: int) -> list[tuple[str, str]]:
    """Return ``(detector, token)`` pairs: one of every documented shape, seeded."""
    rng = random.Random(seed)
    fake = "FAKE" + _pick(rng, ALNUM, 4)
    out = [
        ("aws_key", rng.choice(["AKIA", "ASIA", "ABIA", "ACCA"]) + _pick(rng, B32, 9) + "EXAMPLE"),
        ("github_token", rng.choice("pousr").join(["gh", "_"]) + fake + _pick(rng, ALNUM, 28)),
        ("github_token", "ghs_" + str(rng.randint(1, 10**7)) + "_" + jwt(rng)),
        ("github_pat", "github_pat_" + fake + _pick(rng, ALNUM, 14) + "_" + _pick(rng, ALNUM, 59)),
        ("jwt", jwt(rng)),
        ("openai_key", "sk-" + fake + _pick(rng, ALNUM, 12) + "T3BlbkFJ" + _pick(rng, ALNUM, 20)),
        (
            "openai_key",
            "sk-proj-" + fake + _pick(rng, B64URL, 66) + "T3BlbkFJ" + _pick(rng, ALNUM, 74),
        ),
        (
            "stripe_key",
            rng.choice(["sk", "rk"])
            + "_"
            + rng.choice(["live", "test"])
            + "_"
            + fake
            + _pick(rng, ALNUM, rng.randint(16, 91)),
        ),
        ("stripe_key", "whsec_" + fake + _pick(rng, ALNUM, 24)),
        (
            "slack_token",
            "xoxb-"
            + _pick(rng, string.digits, 12)
            + "-"
            + _pick(rng, string.digits, 13)
            + "-"
            + fake
            + _pick(rng, ALNUM, 16),
        ),
        (
            "slack_token",
            "xoxp-"
            + "-".join(_pick(rng, string.digits, 12) for _ in range(3))
            + "-"
            + fake.lower()
            + _pick(rng, string.hexdigits.lower(), 24),
        ),
        (
            "slack_token",
            "xapp-1-A"
            + _pick(rng, string.ascii_uppercase + string.digits, 10)
            + "-"
            + _pick(rng, string.digits, 13)
            + "-"
            + _pick(rng, "0123456789abcdef", 64),
        ),
        ("google_api_key", "AIza" + fake + _pick(rng, B64URL, 27)),
        (
            "private_key",
            pem(
                rng,
                rng.choice(
                    [
                        "PRIVATE KEY",
                        "RSA PRIVATE KEY",
                        "EC PRIVATE KEY",
                        "OPENSSH PRIVATE KEY",
                        "ENCRYPTED PRIVATE KEY",
                        "PGP PRIVATE KEY BLOCK",
                    ]
                ),
            ),
        ),
        (
            "credit_card",
            card(
                rng, rng.choice(["4", "51", "2221", "34", "37", "6011"]), rng.choice([15, 16, 19])
            ),
        ),
        ("email", _pick(rng, string.ascii_lowercase, 6) + "." + fake.lower() + "@example.com"),
    ]
    return out


def slack_webhook(rng: random.Random) -> tuple[str, str]:
    """Return a fake incoming-webhook URL and the part of it that is the secret."""
    path = "T" + _pick(rng, B32, 8) + "/B" + _pick(rng, B32, 8) + "/FAKE" + _pick(rng, ALNUM, 20)
    return "https://hooks.slack.com/services/" + path, path


KEY_NAMES = [
    "password",
    "db_password",
    "dbPassword",
    "api_key",
    "apiKey",
    "secret",
    "client_secret",
    "AWS_SECRET_ACCESS_KEY",
    "auth_token",
    "private_key",
    "PASSWORD",
    "passwd",
    "pwd",
    "token",
    "access_key",
    "secret_key",
    "secretKey",
    "credentials",
    "session_key",
    "x-api-key",
]
KEY_FORMATS = [
    "{k}={v}",
    "{k}: {v}",
    '"{k}": "{v}"',
    '{k} = "{v}"',
    "export {k}='{v}'",
    "{k} := {v}",
    "$config['{k}'] = '{v}';",
    "{k} => '{v}'",
    "{k}={v};other=1",
    "{k}: '{v}'",
    "{{{k}: {v}}}",
]


def token_lines(seed: int) -> list[str]:
    """Log-like lines that carry each generated token in a different context."""
    lines = []
    for _, token in tokens(seed):
        lines += [f"x {token} y", f'export K="{token}"', f"curl -H 'X-Auth: {token}'"]
    return lines


def keyword_lines(seed: int) -> list[str]:
    """``key = value`` lines: every key name in every syntax, with fake values."""
    rng = random.Random(seed)
    lines = []
    for key in KEY_NAMES:
        for form in KEY_FORMATS:
            value = "Fk" + _pick(rng, ALNUM, 14)
            lines.append(form.format(k=key, v=value))
    return lines
