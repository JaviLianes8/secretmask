"""More detector shapes: hyphen starts, escaped connection values, documented forms."""

from __future__ import annotations

from secretmask import MaskConfig, mask_text

from ._corpus import tokens

LABEL = MaskConfig(strategy="label")


def test_tokens_after_a_hyphen_or_underscore_are_found() -> None:
    for token in ("ghp_" + "a" * 36, "sk-" + "a" * 20, "sk_live_" + "a" * 16):
        for left in ("x-", "x_", "-", "_"):
            assert mask_text(left + token) == left + "***", left + token


def test_escaped_connection_values_are_one_secret() -> None:
    config = MaskConfig(strategy="partial", keep_last=3)
    for value in ('"pa""rest"', "'pa''rest'", "{pa}}rest}"):
        expected = "*" * (len(value) - 3) + value[-3:]
        assert mask_text(f"Password={value};x", config=config) == f"Password={expected};x"


def test_more_documented_shapes() -> None:
    jwe = ".".join(["eyJhbGciOiJSU0EifQ", "a" * 20, "b" * 16, "c" * 30, "d" * 22])
    assert mask_text(f"[{jwe}]", config=LABEL) == "[<redacted:jwt>]"
    assert mask_text("whsec_" + "Ab+/=" * 6, config=LABEL) == "<redacted:stripe_key>"
    assert mask_text("ghs_1_" + tokens(3)[4][1], config=LABEL) == "<redacted:github_token>"
    assert mask_text("h-xoxb-123456789012-FAKE") == "h-***"
    for kept in ("a.xoxb-123456789012-FAKE", "7xoxb-123456789012-FAKE"):
        assert mask_text(kept) == kept
    for prefix in ("xoxe-1-", "xoxr-", "xoxe.xoxp-1-", "xoxa-2-"):
        assert mask_text(prefix + "FAKE" + "0" * 20, config=LABEL) == "<redacted:slack_token>"
    for kind in ("workflows", "triggers"):
        url = f"https://hooks.slack.com/{kind}/T0FAKE/A0FAKE/1234/abcdefghijklmnopqrst"
        assert mask_text(url, config=LABEL).endswith("/<redacted:slack_webhook>")
    pem = "-----BEGIN PRIVATE KEY-----\nMIIab----cdEF\n-----END PRIVATE KEY-----"
    assert mask_text(pem) == "***"
