"""Configuration: custom placeholder, extra patterns and keys, opting out."""

from __future__ import annotations

from secretmask import MaskConfig, SecretMask, mask, mask_text


def test_custom_placeholder() -> None:
    assert mask({"password": "p"}, config=MaskConfig(placeholder="[hidden]")) == {
        "password": "[hidden]"
    }


def test_extra_sensitive_key() -> None:
    config = MaskConfig(extra_keys=("iban",))
    assert mask({"iban": "ES00"}, config=config) == {"iban": "***"}


def test_extra_pattern() -> None:
    config = MaskConfig(extra_patterns=(("ticket", r"TCK-\d{4}"),))
    assert mask_text("see TCK-1234", config=config) == "see ***"


def test_disabling_builtin_patterns_leaves_emails_alone() -> None:
    config = MaskConfig(use_builtin_patterns=False)
    assert mask_text("a@b.io", config=config) == "a@b.io"


def test_disabling_builtin_keys_leaves_passwords_alone() -> None:
    config = MaskConfig(use_builtin_keys=False)
    assert mask({"password": "p"}, config=config) == {"password": "p"}


def test_disabling_card_masking() -> None:
    config = MaskConfig(mask_credit_cards=False)
    assert mask_text("4111 1111 1111 1111", config=config) == "4111 1111 1111 1111"


def test_a_reused_masker_compiles_once_and_repeats() -> None:
    masker = SecretMask(MaskConfig(placeholder="X"))
    assert masker.mask_text("a@b.io") == "X"
    assert masker.mask({"token": "t"}) == {"token": "X"}
