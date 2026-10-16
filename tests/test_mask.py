"""Recursive masking of nested data: shapes, types, depth and cycles."""

from __future__ import annotations

from collections import OrderedDict, namedtuple
from types import MappingProxyType

import pytest

from secretmask import mask


def test_masks_sensitive_values_and_scans_the_rest() -> None:
    data = {"users": [{"name": "ada", "secret": "s", "note": "mail a@b.io"}], "n": 3}
    assert mask(data) == {"users": [{"name": "ada", "secret": "***", "note": "mail ***"}], "n": 3}


def test_mappings_become_dicts_in_their_order() -> None:
    source = OrderedDict([("b", "a@b.io"), ("token", "t")])
    out = mask(source)
    assert type(out) is dict and list(out) == ["b", "token"]
    assert mask(MappingProxyType({"pwd": "x"})) == {"pwd": "***"}


def test_lists_stay_lists_and_tuples_become_plain_tuples() -> None:
    Pair = namedtuple("Pair", "left right")
    assert mask(["a@b.io", ("a@b.io", 2)]) == ["***", ("***", 2)]
    out = mask(Pair("a@b.io", 1))
    assert type(out) is tuple and out == ("***", 1)


def test_values_it_does_not_walk_are_returned_as_they_are() -> None:
    items = {"a@b.io"}
    raw = b"password=hunter2"
    out = mask({"set": items, "bytes": raw, "n": None})
    assert out["set"] is items and out["bytes"] is raw and out["n"] is None


def test_a_string_alone_is_scanned() -> None:
    assert mask("Bearer abc123def456ghi") == "Bearer ***"


def test_deep_nesting_is_not_limited_by_the_recursion_limit() -> None:
    data: object = {"pwd": "x", "v": "a@b.io"}
    for _ in range(50_000):
        data = [data]
    out = mask(data)
    for _ in range(50_000):
        assert isinstance(out, list)
        out = out[0]
    assert out == {"pwd": "***", "v": "***"}


def test_a_structure_that_contains_itself_raises_value_error() -> None:
    loop: list[object] = ["a@b.io"]
    loop.append(loop)
    with pytest.raises(ValueError, match="contains itself"):
        mask(loop)
    cyclic: dict[str, object] = {}
    cyclic["self"] = {"inner": cyclic}
    with pytest.raises(ValueError, match="contains itself"):
        mask(cyclic)


def test_a_shared_object_that_is_not_a_cycle_is_masked_twice() -> None:
    shared = {"token": "t"}
    assert mask([shared, shared, {"a": shared}]) == [
        {"token": "***"},
        {"token": "***"},
        {"a": {"token": "***"}},
    ]


def test_a_cycle_under_a_sensitive_key_is_never_walked() -> None:
    loop: dict[str, object] = {}
    loop["auth"] = loop
    assert mask(loop) == {"auth": "***"}


def test_the_input_is_never_changed() -> None:
    data = {"password": "p", "items": [{"token": "t"}], "t": ("a@b.io",)}
    before = repr(data)
    mask(data)
    assert repr(data) == before
