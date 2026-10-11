"""Masking strategies: full, label, partial and hash, in text and in dicts."""

from __future__ import annotations

import hashlib

import pytest

from secretmask import MaskConfig, SecretMask, Strategy, mask, mask_text


def test_strategy_is_a_string_enum() -> None:
    assert Strategy("partial") is Strategy.PARTIAL
    assert Strategy.HASH == "hash"


def test_full_strategy_uses_the_placeholder() -> None:
    assert mask_text("a@b.io", config=MaskConfig(strategy="full", placeholder="[x]")) == "[x]"


def test_label_strategy_names_the_detector() -> None:
    assert mask_text("a@b.io", config=MaskConfig(strategy="label")) == "<redacted:email>"


def test_label_flag_still_maps_to_the_label_strategy() -> None:
    assert mask_text("a@b.io", config=MaskConfig(label=True)) == "<redacted:email>"


def test_partial_keeps_the_last_n_characters() -> None:
    out = mask_text("Bearer abcdefghij", config=MaskConfig(strategy="partial", keep_last=3))
    assert out == "Bearer *******hij"


def test_partial_masks_a_short_secret_in_full() -> None:
    out = mask_text("Bearer abcdefgh", config=MaskConfig(strategy="partial", keep_last=20))
    assert out == "Bearer ***"


def test_hash_is_deterministic_and_short() -> None:
    config = MaskConfig(strategy="hash", hash_length=8)
    out = mask_text("mail a@b.io", config=config)
    digest = hashlib.sha256(b"a@b.io").hexdigest()[:8]
    assert out == f"mail <sha256:{digest}>"


def test_strategy_applies_to_sensitive_dict_values() -> None:
    assert mask({"password": "hunter2"}, config=MaskConfig(strategy="partial", keep_last=2)) == {
        "password": "*****r2"
    }


def test_hash_strategy_on_a_dict_value_is_stable() -> None:
    masker = SecretMask(MaskConfig(strategy="hash"))
    assert masker.mask({"token": "abc"})["token"] == masker.mask({"secret": "abc"})["secret"]


def test_partial_falls_back_for_a_masked_subtree() -> None:
    # The value under a sensitive key is a subtree, not a string: partial cannot
    # keep characters of it, so it falls back to the placeholder.
    assert mask({"auth": {"a": 1}}, config=MaskConfig(strategy="partial")) == {"auth": "***"}


def test_rejects_a_negative_keep_last() -> None:
    with pytest.raises(ValueError):
        MaskConfig(keep_last=-1)


def test_rejects_an_out_of_range_hash_length() -> None:
    with pytest.raises(ValueError):
        MaskConfig(hash_length=0)
    with pytest.raises(ValueError):
        MaskConfig(hash_length=65)
