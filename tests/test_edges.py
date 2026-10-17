"""Edge cases a blind mutation round found unpinned: each test fixes one behaviour."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from secretmask import MaskConfig, mask, mask_text

BACKSLASH = chr(92)


def test_quoted_values_keep_their_escapes_inside_the_secret() -> None:
    assert mask_text("Pwd='a''b c" + BACKSLASH + "'") == "Pwd=***"
    assert mask_text('password="a' + BACKSLASH + '"b c"') == "password=***"


def test_a_bare_value_stops_at_a_comma() -> None:
    assert mask_text("token=a,b") == "token=***,b"


def test_touching_spans_stay_hidden_when_only_one_is_allowlisted() -> None:
    config = MaskConfig(extra_patterns=(("a", "AAA"), ("b", "BBB")), allowlist=("AAA",))
    assert mask_text("AAABBB", config=config) == "***"


def test_an_unmatched_named_group_hides_the_whole_match() -> None:
    config = MaskConfig(extra_patterns=(("x", r"id=(?P<s>\d+)?"),))
    assert mask_text("id= x", config=config) == "*** x"


def test_every_occurrence_of_a_name_in_a_key_is_checked() -> None:
    assert mask({"tokenizer_token": "x"}) == {"tokenizer_token": "***"}


def test_an_extra_key_without_letters_or_digits_matches_nothing() -> None:
    assert mask({"user": "ada"}, config=MaskConfig(extra_keys=("-",))) == {"user": "ada"}


def test_full_length_digests_and_empty_labels_are_recognised() -> None:
    config = MaskConfig(strategy="hash", hash_length=64)
    once = mask_text("password=hunter2", config=config)
    assert mask_text(once, config=config) == once
    assert mask_text("password=<redacted:>") == "password=<redacted:>"


def test_an_empty_placeholder_removes_secrets_and_settles() -> None:
    config = MaskConfig(placeholder="")
    assert mask_text("password=hunter2", config=config) == "password="
    assert mask_text("a a@b.io b", config=config) == "a  b"


def test_hashing_keeps_lone_surrogates_and_reads_keys_as_utf8() -> None:
    secret = "x" + chr(0xDC80)
    expected = hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    out = mask_text("password=" + secret, config=MaskConfig(strategy="hash"))
    assert out == f"password=<sha256:{expected}>"
    mac = hmac.new("clé".encode(), b"hunter2", hashlib.sha256).hexdigest()[:8]
    keyed = MaskConfig(strategy="hash", hash_key="clé")
    assert mask_text("password=hunter2", config=keyed) == f"password=<sha256:{mac}>"


def test_builtins_run_before_extra_patterns() -> None:
    config = MaskConfig(strategy="label", extra_patterns=(("mine", r"ghp_\w+"),))
    assert mask_text("ghp_" + "a" * 36, config=config) == "<redacted:github_token>"


def test_bytes_where_strings_are_expected_name_the_whole_value() -> None:
    with pytest.raises(TypeError, match="allowlist must be a tuple of strings, got bytes"):
        MaskConfig(allowlist=b"ab")  # type: ignore[arg-type]


@pytest.mark.parametrize("regex", ["a{4294967296}", "(" * 500 + ")" * 500])
def test_a_regex_too_large_to_compile_is_a_value_error(regex: str) -> None:
    with pytest.raises(ValueError, match="too large or nested to compile"):
        MaskConfig(extra_patterns=(("x", regex),))
