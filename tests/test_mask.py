"""Recursive masking of nested data structures."""

from __future__ import annotations

from secretmask import mask


def test_masks_the_value_of_a_sensitive_key() -> None:
    assert mask({"password": "hunter2"}) == {"password": "***"}


def test_matches_sensitive_keys_case_insensitively() -> None:
    assert mask({"API_Key": "xyz"}) == {"API_Key": "***"}


def test_matches_sensitive_keys_ignoring_separators() -> None:
    assert mask({"access-token": "xyz"}) == {"access-token": "***"}


def test_recurses_into_nested_mappings_and_lists() -> None:
    data = {"users": [{"name": "ada", "secret": "s"}]}
    assert mask(data) == {"users": [{"name": "ada", "secret": "***"}]}


def test_redacts_a_whole_subtree_under_a_sensitive_key() -> None:
    assert mask({"auth": {"token": "t", "note": "n"}}) == {"auth": "***"}


def test_pattern_redaction_still_applies_to_plain_string_values() -> None:
    assert mask({"log": "mail a@b.io"}) == {"log": "mail ***"}


def test_leaves_non_sensitive_values_unchanged() -> None:
    assert mask({"count": 3, "ok": True, "ratio": 1.5}) == {"count": 3, "ok": True, "ratio": 1.5}


def test_does_not_mutate_the_input() -> None:
    data = {"password": "p", "items": [{"token": "t"}]}
    mask(data)
    assert data == {"password": "p", "items": [{"token": "t"}]}


def test_preserves_tuple_type() -> None:
    assert mask(("a@b.io", 1)) == ("***", 1)


def test_non_string_keys_are_never_treated_as_sensitive() -> None:
    assert mask({1: "a@b.io", None: "x"}) == {1: "***", None: "x"}
