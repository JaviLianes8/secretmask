"""Ground truth from each vendor's own documentation and from the RFCs, fetched live.

The copies come from ``scripts/fetch_sources.py`` (URLs, dates and hashes in
``tests/sources/MANIFEST.json``); each test skips when its copy is absent. Facts are
read from the copies at run time: prefixes, documented examples and test numbers.
"""

from __future__ import annotations

import html
import random
import re
from pathlib import Path

import pytest

from secretmask import MaskConfig, mask_text
from secretmask._cards import luhn_ok

from ._corpus import ALNUM, B32, jwt

SOURCES = Path(__file__).resolve().parent / "sources"
LABEL = MaskConfig(strategy="label")


def _read(name: str, *, strip_html: bool = False) -> str:
    path = SOURCES / name
    if not path.is_file():
        pytest.skip(f"{name} not fetched; run scripts/fetch_sources.py")
    text = path.read_text("utf-8")
    if strip_html:
        text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return re.sub(r"[ \t\r\n]+", " ", text) if strip_html else text


def _label(token: str) -> str:
    out = mask_text(f"[{token}]", config=LABEL)
    assert token not in out
    match = re.fullmatch(r"\[<redacted:(\w+)>\]", out)
    assert match, out
    return match.group(1)


def test_aws_credential_prefixes_are_hidden_and_other_ids_are_not() -> None:
    text = _read("aws-iam-identifiers.html", strip_html=True)
    start = text.index("Prefix Resource type")
    table = text[start : text.index("Getting the unique identifier", start)]
    rows = dict(re.findall(r"\b(A[A-Z0-9]{3}) (.+?)(?= A[A-Z0-9]{3} |$)", table[21:]))
    secret = {
        p for p, what in rows.items() if re.search(r"access key|bearer|credential", what, re.I)
    }
    assert secret == {"ABIA", "ACCA", "AKIA", "ASIA"}
    assert len(rows) == 12
    rng = random.Random(1)
    for prefix in rows:
        key = prefix + "".join(rng.choice(B32) for _ in range(9)) + "EXAMPLE"
        assert (mask_text(key) == "***") is (prefix in secret), key
    for example in set(re.findall(r"\b(A[A-Z]{3}[A-Z0-9]{16})\b", text)):
        assert (mask_text(example) == "***") is (example[:4] in secret), example


def test_github_documented_token_prefixes() -> None:
    text = _read("github-authentication.md")
    prefixes = set(re.findall(r"\| `([a-z_]+_)` +\|", text))
    assert prefixes == {"ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_"}
    assert "`ghs_APPID_JWT`" in text
    rng = random.Random(2)
    for prefix in prefixes:
        if prefix == "github_pat_":
            body = "".join(rng.choice(ALNUM) for _ in range(22)) + "_" + "x" * 59
        else:
            body = "".join(rng.choice(ALNUM) for _ in range(36))
        assert _label(prefix + body) in {"github_token", "github_pat"}
    assert _label(f"ghs_{rng.randint(1, 10**6)}_{jwt(rng)}") == "github_token"


def test_stripe_secret_and_restricted_keys_but_not_publishable_ones() -> None:
    text = _read("stripe-keys.md") + _read("stripe-webhook-signature.md")
    prefixes = set(re.findall(r"`((?:sk|rk|pk)_[a-z]+_|whsec_)", text))
    assert {"sk_live_", "rk_live_", "sk_test_", "rk_test_", "pk_live_", "pk_test_"} <= prefixes
    assert {"sk_org_", "whsec_"} <= prefixes
    for prefix in sorted(prefixes):
        token = prefix + "FAKE" + "0" * 28
        assert (mask_text(token) == "***") is (not prefix.startswith("pk_")), token


def test_stripe_documented_test_card_numbers_are_hidden() -> None:
    text = _read("stripe-testing.md")
    numbers = {n for n in re.findall(r"(?<![0-9])[0-9]{13,19}(?![0-9])", text) if luhn_ok(n)}
    assert len(numbers) >= 30
    for number in numbers:
        assert mask_text(f"card {number} ok", config=LABEL) == "card <redacted:credit_card> ok"


def test_slack_documented_prefixes_and_examples() -> None:
    text = _read("slack-tokens.html", strip_html=True)
    found = set(re.findall(r"\b((?:xoxe\.)?(?:xox[a-z]|xapp|xwfp)-)[A-Za-z0-9-]*", text))
    assert {"xoxb-", "xoxp-", "xapp-", "xoxe.xapp-", "xwfp-"} <= found
    for prefix in found:
        assert _label(prefix + "1-FAKE-" + "0" * 20) == "slack_token"
    examples = set(re.findall(r"\bxoxp-[0-9]+-[0-9]+-[0-9]+-[0-9a-f]+", text))
    assert len(examples) >= 3
    for example in examples:
        assert _label(example) == "slack_token"


def test_google_documented_api_key_example() -> None:
    page = _read("google-api-keys.html")
    examples = re.findall(r"<code[^>]*>(AIza[0-9A-Za-z_-]{35})</code>", page)
    assert examples
    for example in examples:
        assert _label(example) == "google_api_key"


def _rfc_jwts(text: str) -> list[str]:
    # The RFC prints each JWT with display line breaks; join the indented lines.
    blocks = re.findall(
        r"complete JWT \(with line\s+breaks for display purposes only\):\n\n((?:\s+\S+\n)+)", text
    )
    return ["".join(block.split()) for block in blocks]


def test_rfc7519_example_jwts_signed_and_unsecured() -> None:
    tokens = _rfc_jwts(_read("rfc7519.txt"))
    assert len(tokens) == 2 and tokens[1].endswith(".")
    for token in tokens:
        assert _label(token) == "jwt"


def test_rfc7468_private_key_blocks_hidden_and_public_ones_kept() -> None:
    text = _read("rfc7468.txt")
    blocks = re.findall(
        r"^(-----BEGIN ([A-Z0-9 .]+)-----\n.*?\n-----END \2-----)$", text, re.S | re.M
    )
    labels = {label for _, label in blocks}
    assert {"PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PUBLIC KEY", "CERTIFICATE"} <= labels
    for block, label in blocks:
        out = mask_text(f"key:\n{block}\nend", config=LABEL)
        if "PRIVATE KEY" in label:
            assert out == "key:\n<redacted:private_key>\nend"
        else:
            assert out == f"key:\n{block}\nend"


def test_rfc4880_private_key_armor_hidden_and_messages_kept() -> None:
    text = _read("rfc4880.txt")
    assert "BEGIN PGP PRIVATE KEY BLOCK" in text and "BEGIN PGP PUBLIC KEY BLOCK" in text
    rng = random.Random(4)
    body = "\n".join("".join(rng.choice(ALNUM + "+/") for _ in range(64)) for _ in range(3))
    for kind, hidden in (("PRIVATE KEY BLOCK", True), ("PUBLIC KEY BLOCK", False)):
        armor = f"-----BEGIN PGP {kind}-----\nVersion: x\n\n{body}\n=njUN\n-----END PGP {kind}-----"
        assert (mask_text(armor) == "***") is hidden
    message = re.search(r"-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----", text, re.S)
    assert message is not None
    plain = re.sub(r"\n +", "\n", message.group(0))
    assert mask_text(plain) == plain


def test_rfc7617_basic_and_rfc6750_bearer_examples() -> None:
    basic = re.findall(r"^ +((?:Proxy-)?Authorization: Basic (\S+))$", _read("rfc7617.txt"), re.M)
    assert len(basic) == 3
    for line, credential in basic:
        assert mask_text(line, config=LABEL) == line.replace(credential, "<redacted:basic_auth>")
    lines = [ln.strip() for ln in _read("rfc6750.txt").splitlines() if "mF_9.B5f-4.1JqM" in ln]
    assert len(lines) >= 5
    for line in lines:
        out = mask_text(line)
        assert "mF_9" not in out and "B5f-4" not in out, out
    assert mask_text("resource?access_token=mF_9.B5f-4.1JqM&p=q") == "resource?access_token=***&p=q"
