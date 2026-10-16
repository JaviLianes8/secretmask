"""Strategies: full, label, partial and hash, in text and for sensitive keys."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from secretmask import MaskConfig, SecretMask, Strategy, mask, mask_text


def test_full_label_partial_and_hash_in_text() -> None:
    text = "mail a@b.io"
    assert mask_text(text, config=MaskConfig(strategy="full", placeholder="[x]")) == "mail [x]"
    assert mask_text(text, config=MaskConfig(strategy=Strategy.LABEL)) == "mail <redacted:email>"
    assert mask_text(text, config=MaskConfig(label=True)) == "mail <redacted:email>"
    assert mask_text(text, config=MaskConfig(strategy="partial", keep_last=3)) == "mail ***.io"
    digest = hashlib.sha256(b"a@b.io").hexdigest()[:8]
    assert mask_text(text, config=MaskConfig(strategy="hash")) == f"mail <sha256:{digest}>"


def test_strategy_wins_over_the_label_flag() -> None:
    assert mask_text("a@b.io", config=MaskConfig(label=True, strategy="full")) == "***"


def test_partial_keeps_the_tail_and_hides_short_secrets_whole() -> None:
    config = MaskConfig(strategy="partial", keep_last=3)
    assert mask_text("Bearer abcdefghij", config=config) == "Bearer *******hij"
    for keep in (8, 0):
        config = MaskConfig(strategy="partial", keep_last=keep)
        assert mask_text("Bearer abcdefgh", config=config) == "Bearer ***"


def test_hash_length_and_hash_key() -> None:
    plain = MaskConfig(strategy="hash", hash_length=64)
    full = hashlib.sha256(b"a@b.io").hexdigest()
    assert mask_text("a@b.io", config=plain) == f"<sha256:{full}>"
    keyed = MaskConfig(strategy="hash", hash_key="pepper", hash_length=12)
    mac = hmac.new(b"pepper", b"a@b.io", hashlib.sha256).hexdigest()
    assert mask_text("a@b.io", config=keyed) == f"<sha256:{mac[:12]}>"
    as_bytes = MaskConfig(strategy="hash", hash_key=b"pepper")
    assert mask_text("a@b.io", config=as_bytes) == f"<sha256:{mac[:8]}>"


def test_hash_correlates_equal_secrets_across_text_and_keys() -> None:
    masker = SecretMask(MaskConfig(strategy="hash"))
    assert masker.mask({"token": "abc"})["token"] == masker.mask({"secret": "abc"})["secret"]
    assert masker.mask_text("ping a@b.io") == "ping " + masker.mask({"pwd": "a@b.io"})["pwd"]


@pytest.mark.parametrize(
    ("strategy", "expected"),
    [
        ("full", "***"),
        ("label", "<redacted:password>"),
        ("partial", "*****r2"),
        ("hash", "<sha256:" + hashlib.sha256(b"hunter2").hexdigest()[:8] + ">"),
    ],
)
def test_strategies_apply_to_sensitive_key_values(strategy: str, expected: str) -> None:
    config = MaskConfig(strategy=strategy, keep_last=2)
    assert mask({"password": "hunter2"}, config=config) == {"password": expected}


@pytest.mark.parametrize("strategy", ["partial", "hash", "full"])
def test_a_non_string_value_under_a_sensitive_key_gets_the_placeholder(strategy: str) -> None:
    config = MaskConfig(strategy=strategy)
    assert mask({"auth": {"a": 1}, "pin": 1234, "pwd": None}, config=config) == {
        "auth": "***",
        "pin": 1234,
        "pwd": "***",
    }


def test_label_names_the_key_for_values_of_any_type() -> None:
    config = MaskConfig(strategy="label")
    assert mask({"db_password": 5}, config=config) == {"db_password": "<redacted:db_password>"}


def test_allowlisted_values_are_kept_under_every_strategy() -> None:
    for strategy in Strategy:
        config = MaskConfig(strategy=strategy, allowlist=("keep-me", "a@b.io"))
        assert mask({"token": "keep-me", "n": "a@b.io"}, config=config) == {
            "token": "keep-me",
            "n": "a@b.io",
        }
