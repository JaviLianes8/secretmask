"""Configuration: what it accepts, what it refuses, and the errors it raises."""

from __future__ import annotations

from typing import Any

import pytest

from secretmask import MaskConfig, SecretMask, mask, mask_text


def test_custom_placeholder_extra_keys_and_patterns() -> None:
    config = MaskConfig(
        placeholder="[hidden]", extra_keys=("iban",), extra_patterns=(("ticket", r"TCK-\d{4}"),)
    )
    assert mask({"iban": "ES00", "n": "see TCK-1234"}, config=config) == {
        "iban": "[hidden]",
        "n": "see [hidden]",
    }


def test_builtins_can_be_switched_off() -> None:
    config = MaskConfig(use_builtin_patterns=False, mask_credit_cards=False)
    assert mask_text("a@b.io 4242 4242 4242 4242", config=config) == "a@b.io 4242 4242 4242 4242"
    assert mask({"password": "p"}, config=MaskConfig(use_builtin_keys=False)) == {"password": "p"}


def test_extra_patterns_run_after_the_builtins_and_may_hide_a_part() -> None:
    config = MaskConfig(extra_patterns=(("pin", r"PIN (?P<s>\d{4})"), ("all", r"[a-z]+@")))
    assert mask_text("PIN 1234 and a@b.io", config=config) == "PIN *** and ***"


def test_an_extra_pattern_that_matches_empty_text_changes_nothing() -> None:
    config = MaskConfig(extra_patterns=(("empty", r"x*"),))
    assert mask_text("abc", config=config) == "abc"


def test_lists_are_accepted_and_stored_as_tuples() -> None:
    config = MaskConfig(
        extra_patterns=[("t", "T-1")],  # type: ignore[arg-type]
        extra_keys=["iban"],  # type: ignore[arg-type]
        allowlist=["a@b.io"],  # type: ignore[arg-type]
    )
    assert config.extra_patterns == (("t", "T-1"),)
    assert config.extra_keys == ("iban",)
    assert config.allowlist == ("a@b.io",)


TYPE_ERRORS: list[tuple[dict[str, Any], str]] = [
    ({"placeholder": None}, "placeholder must be a str, got NoneType"),
    ({"keep_last": 2.0}, "keep_last must be an int, got float"),
    ({"keep_last": True}, "keep_last must be an int, got bool"),
    ({"hash_length": "8"}, "hash_length must be an int, got str"),
    ({"label": 1}, "label must be a bool, got int"),
    ({"mask_credit_cards": None}, "mask_credit_cards must be a bool, got NoneType"),
    ({"strategy": 3}, "strategy must be a Strategy or str, got int"),
    ({"hash_key": 5}, "hash_key must be str or bytes, got int"),
    ({"allowlist": "a@b.io"}, "allowlist must be a tuple of strings, got str"),
    ({"extra_keys": ("a", 1)}, "extra_keys must hold strings, got int"),
    ({"extra_patterns": "abc"}, "extra_patterns must be a tuple of (name, regex) pairs"),
    ({"extra_patterns": (("a", "b", "c"),)}, "extra_patterns must hold (name, regex) pairs"),
    ({"extra_patterns": (("a", 1),)}, "a (name, regex) pair must hold two strings"),
]


@pytest.mark.parametrize(("kwargs", "message"), TYPE_ERRORS)
def test_wrong_types_raise_type_error(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(TypeError) as info:
        MaskConfig(**kwargs)
    assert str(info.value) == message


VALUE_ERRORS: list[tuple[dict[str, Any], str]] = [
    ({"keep_last": -1}, "keep_last must be at least 0, got -1"),
    ({"hash_length": 0}, "hash_length must be between 1 and 64, got 0"),
    ({"hash_length": 65}, "hash_length must be between 1 and 64, got 65"),
    ({"strategy": "mask"}, "strategy must be one of full, label, partial, hash, got 'mask'"),
    ({"extra_patterns": (("t", "("),)}, "pattern 't' is not a valid regex: missing ),"),
    ({"extra_patterns": (("bad name", "x"),)}, "pattern name must be 1 to 64 of"),
    ({"extra_patterns": (("", "x"),)}, "pattern name must be 1 to 64 of"),
]


@pytest.mark.parametrize(("kwargs", "message"), VALUE_ERRORS)
def test_bad_values_raise_value_error(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError) as info:
        MaskConfig(**kwargs)
    assert str(info.value).startswith(message)


def test_error_messages_never_echo_long_input() -> None:
    secret = "s3cr3t-" * 1000
    cases: list[dict[str, Any]] = [
        {"strategy": secret},
        {"extra_patterns": ((secret, "x"),)},
        {"extra_patterns": (("n", "(" + secret),)},
        {"keep_last": -(10**5000)},
    ]
    for kwargs in cases:
        with pytest.raises(ValueError) as info:
            MaskConfig(**kwargs)
        assert len(str(info.value)) < 120
        assert secret[:20] not in str(info.value)


def test_a_reused_masker_repeats_itself() -> None:
    masker = SecretMask(MaskConfig(placeholder="X"))
    assert masker.mask_text("a@b.io") == "X"
    assert masker.mask({"token": "t"}) == {"token": "X"}
    assert masker.mask_text("a@b.io") == "X"
