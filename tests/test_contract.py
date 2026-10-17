"""The public contract: names, signatures, types and the whole promise of each name."""

from __future__ import annotations

import dataclasses
import importlib.resources
import inspect
import pickle

import pytest

import secretmask
from secretmask import MaskConfig, SecretMask, Strategy, mask, mask_json, mask_text

PUBLIC_API = ["MaskConfig", "SecretMask", "Strategy", "mask", "mask_json", "mask_text"]

SIGNATURES = {
    "mask": "(value: 'Any', *, config: 'MaskConfig | None' = None) -> 'Any'",
    "mask_text": "(text: 'str', *, config: 'MaskConfig | None' = None) -> 'str'",
    "mask_json": "(text: 'str', *, config: 'MaskConfig | None' = None) -> 'str'",
    "SecretMask": "(config: 'MaskConfig | None' = None) -> 'None'",
}

CONFIG_FIELDS = {
    "placeholder": "***",
    "extra_patterns": (),
    "extra_keys": (),
    "allowlist": (),
    "use_builtin_patterns": True,
    "use_builtin_keys": True,
    "mask_credit_cards": True,
    "label": False,
    "strategy": None,
    "keep_last": 4,
    "hash_length": 8,
    "hash_key": None,
}


def test_all_lists_exactly_the_public_api() -> None:
    assert sorted(secretmask.__all__) == sorted(PUBLIC_API)
    public = {name for name in dir(secretmask) if not name.startswith("_")}
    assert public == set(PUBLIC_API)


def test_every_public_name_reports_the_package_as_its_module() -> None:
    for name in PUBLIC_API:
        assert getattr(secretmask, name).__module__ == "secretmask"


def test_version_is_one_point_zero() -> None:
    assert secretmask.__version__ == "1.0.0"


def test_the_package_ships_type_information() -> None:
    assert importlib.resources.files("secretmask").joinpath("py.typed").is_file()


@pytest.mark.parametrize(("name", "expected"), sorted(SIGNATURES.items()))
def test_signatures_are_frozen(name: str, expected: str) -> None:
    assert str(inspect.signature(getattr(secretmask, name))) == expected


def test_config_fields_and_defaults_are_frozen() -> None:
    fields = [f for f in dataclasses.fields(MaskConfig) if f.init]
    assert [f.name for f in fields] == list(CONFIG_FIELDS)
    assert {f.name: f.default for f in fields} == CONFIG_FIELDS
    assert all(f.kw_only is False for f in fields)


def test_config_is_frozen_hashable_comparable_and_pickles() -> None:
    config = MaskConfig(extra_keys=["iban"], strategy="hash", hash_key="k")  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.placeholder = "x"  # type: ignore[misc]
    assert config.extra_keys == ("iban",)
    assert config == MaskConfig(extra_keys=("iban",), strategy="hash", hash_key="k")
    assert hash(config) == hash(MaskConfig(extra_keys=("iban",), strategy="hash", hash_key="k"))
    clone = pickle.loads(pickle.dumps(config))
    assert clone == config
    assert mask_text("a@b.io", config=clone) == mask_text("a@b.io", config=config)
    assert "hash_key" not in repr(config)


def test_strategy_members_are_frozen() -> None:
    assert [(s.name, s.value) for s in Strategy] == [
        ("FULL", "full"),
        ("LABEL", "label"),
        ("PARTIAL", "partial"),
        ("HASH", "hash"),
    ]
    assert isinstance(Strategy.FULL, str)


def test_secret_mask_exposes_its_config() -> None:
    config = MaskConfig(placeholder="#")
    masker = SecretMask(config)
    assert masker.config is config
    assert SecretMask().config == MaskConfig()
    assert repr(masker).startswith("SecretMask(MaskConfig(placeholder='#'")


def test_module_functions_equal_a_masker_with_the_same_config() -> None:
    config = MaskConfig(strategy="label")
    masker = SecretMask(config)
    text = "Bearer abc123def456ghi mail a@b.io"
    assert mask_text(text, config=config) == masker.mask_text(text)
    assert mask({"pwd": text}, config=config) == masker.mask({"pwd": text})
    assert mask_json('{"t": "a@b.io"}', config=config) == masker.mask_json('{"t": "a@b.io"}')
    assert mask_text(text) == SecretMask().mask_text(text) == "Bearer *** mail ***"


def test_mask_never_mutates_and_returns_new_containers() -> None:
    data = {"password": "p", "items": [{"token": "t"}], "pair": ("a@b.io", 1)}
    masked = mask(data)
    assert data == {"password": "p", "items": [{"token": "t"}], "pair": ("a@b.io", 1)}
    assert masked == {"password": "***", "items": [{"token": "***"}], "pair": ("***", 1)}
    assert masked is not data and masked["items"] is not data["items"]


def test_mask_returns_other_values_as_they_are() -> None:
    marker = object()
    for value in (None, 3, 1.5, True, b"a@b.io", marker, {1, 2}):
        assert mask(value) is value


@pytest.mark.parametrize("call", [mask_text, mask_json])
def test_text_functions_reject_non_strings(call: object) -> None:
    with pytest.raises(TypeError, match="expects a str, got bytes"):
        call(b"a@b.io")  # type: ignore[operator]


def test_secret_mask_rejects_a_config_of_the_wrong_type() -> None:
    with pytest.raises(TypeError, match="config must be a MaskConfig"):
        SecretMask({"placeholder": "x"})  # type: ignore[arg-type]


def test_mask_json_is_compact_keeps_unicode_and_rejects_bad_json() -> None:
    assert mask_json('{"user": "José", "pwd": 1}') == '{"user": "José", "pwd": "***"}'
    with pytest.raises(ValueError):
        mask_json("{not json")
    with pytest.raises(ValueError, match="nested too deeply"):
        mask_json("[" * 100_000)
