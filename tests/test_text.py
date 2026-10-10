"""Pattern redaction inside free strings."""

from __future__ import annotations

from secretmask import mask_text


def test_redacts_a_jwt() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpM"
    assert token not in mask_text(f"auth={token}")


def test_redacts_an_aws_access_key() -> None:
    assert "AKIAIOSFODNN7EXAMPLE" not in mask_text("key AKIAIOSFODNN7EXAMPLE used")


def test_redacts_an_openai_style_key() -> None:
    assert mask_text("sk-abcdefghijklmnopqrstuvwx") == "***"


def test_redacts_a_github_token() -> None:
    token = "ghp_" + "a" * 36
    assert token not in mask_text(f"token: {token}")


def test_redacts_an_email() -> None:
    assert mask_text("write to jane.doe@example.com now") == "write to *** now"


def test_keeps_the_bearer_label_but_hides_the_token() -> None:
    masked = mask_text("Authorization: Bearer abc123def456ghi")
    assert "Bearer" in masked
    assert "abc123def456ghi" not in masked


def test_redacts_a_luhn_valid_card_number() -> None:
    assert mask_text("card 4111 1111 1111 1111 ok") == "card *** ok"


def test_leaves_a_number_that_fails_luhn() -> None:
    # Right length, wrong checksum: not a card, must survive untouched.
    assert mask_text("ref 1234 5678 9012 3456") == "ref 1234 5678 9012 3456"


def test_leaves_ordinary_text_untouched() -> None:
    assert mask_text("a plain sentence with no secrets") == "a plain sentence with no secrets"


def test_label_mode_names_the_match() -> None:
    from secretmask import MaskConfig

    out = mask_text("mail me@x.io", config=MaskConfig(label=True))
    assert out == "mail <redacted:email>"
