"""The complete promise of secretmask, asserted end to end without mocks.

Every detector, every strategy, dict masking, idempotence and the allowlist are
checked here so a regression in any one of them fails this file.
"""

from __future__ import annotations

import importlib.resources

import pytest

import secretmask
from secretmask import MaskConfig, SecretMask, Strategy, mask, mask_json, mask_text

# The public API. Add every exported name here as the library grows; this list is the
# contract and the test below fails if the module and this list disagree.
PUBLIC_API: list[str] = ["MaskConfig", "SecretMask", "Strategy", "mask", "mask_json", "mask_text"]


def test_all_lists_exactly_the_public_api() -> None:
    assert sorted(secretmask.__all__) == sorted(PUBLIC_API)


def test_every_exported_name_resolves() -> None:
    for name in secretmask.__all__:
        assert hasattr(secretmask, name)


def test_version_is_a_three_part_string() -> None:
    parts = secretmask.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_the_package_ships_type_information() -> None:
    assert importlib.resources.files("secretmask").joinpath("py.typed").is_file()


# One representative, real secret per built-in detector, with the substring that
# must never survive masking.
DETECTOR_CASES: list[tuple[str, str]] = [
    ("auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpM", "SflKxwRJSMeKKF2QT4fwpM"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", "MIIabc"),
    ("key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    ("sk-abcdefghijklmnopqrstuvwx", "sk-abcdefghijklmnopqrstuvwx"),
    ("sk_live_abcdefghijklmnop1234", "sk_live_abcdefghijklmnop1234"),
    ("ghp_" + "a" * 36, "ghp_" + "a" * 36),
    ("xoxb-" + "1" * 12, "xoxb-" + "1" * 12),
    ("AIza" + "b" * 35, "AIza" + "b" * 35),
    ("postgres://user:s3cr3tpw@host/db", "s3cr3tpw"),
    ("Server=a;Password=p4ssword;Db=x", "p4ssword"),
    ("Authorization: Bearer abc123def456ghi", "abc123def456ghi"),
    ("api_key = AbCdEf12345tokenvalue", "AbCdEf12345tokenvalue"),
    ("write to jane.doe@example.com now", "jane.doe@example.com"),
    ("card 4111 1111 1111 1111 ok", "4111 1111 1111 1111"),
]


@pytest.mark.parametrize(("text", "secret"), DETECTOR_CASES)
def test_every_detector_hides_its_secret(text: str, secret: str) -> None:
    assert secret not in mask_text(text)


@pytest.mark.parametrize("strategy", list(Strategy))
def test_every_strategy_hides_the_secret_and_is_idempotent(strategy: Strategy) -> None:
    config = MaskConfig(strategy=strategy)
    blob = "Bearer abc123def456ghi mail me@x.io key AKIAIOSFODNN7EXAMPLE"
    once = mask_text(blob, config=config)
    assert "abc123def456ghi" not in once
    assert "me@x.io" not in once
    assert "AKIAIOSFODNN7EXAMPLE" not in once
    assert mask_text(once, config=config) == once


def test_dict_masking_covers_keys_values_and_nesting() -> None:
    data = {"password": "p", "profile": {"email note": "a@b.io"}, "items": [{"token": "t"}]}
    masked = mask(data)
    assert masked == {
        "password": "***",
        "profile": {"email note": "***"},
        "items": [{"token": "***"}],
    }
    assert data["password"] == "p"


def test_idempotence_holds_for_nested_structures() -> None:
    data = {"password": "hunter2", "log": "mail a@b.io card 4111 1111 1111 1111"}
    once = mask(data)
    assert mask(once) == once


def test_allowlist_keeps_named_values_everywhere() -> None:
    config = MaskConfig(allowlist=("a@b.io", "keepme"))
    assert mask_text("to a@b.io and c@d.io", config=config) == "to a@b.io and ***"
    assert mask({"password": "keepme", "secret": "x"}, config=config) == {
        "password": "keepme",
        "secret": "***",
    }


def test_partial_never_reveals_the_whole_secret() -> None:
    masker = SecretMask(MaskConfig(strategy=Strategy.PARTIAL, keep_last=4))
    out = masker.mask_text("Bearer abc123def456ghi")
    assert "abc123def456ghi" not in out
    assert out.endswith("6ghi")


def test_hash_is_stable_for_equal_secrets() -> None:
    masker = SecretMask(MaskConfig(strategy=Strategy.HASH))
    first = masker.mask_text("mail a@b.io")
    second = masker.mask_text("ping a@b.io")
    assert first.split("mail ")[1] == second.split("ping ")[1]


def test_mask_json_round_trips_and_hides_secrets() -> None:
    out = mask_json('{"password": "p", "user": "ada", "note": "a@b.io"}')
    assert '"user": "ada"' in out
    assert '"p"' not in out
    assert "a@b.io" not in out


def test_mask_json_rejects_invalid_json() -> None:
    with pytest.raises(ValueError):
        mask_json("{not json")
