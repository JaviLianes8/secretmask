"""Robustness cases found by adversarial review: each pins one behaviour."""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping

import pytest

from secretmask import MaskConfig, mask, mask_text

# Noise built from detector fragments that needs several passes to settle under the
# partial strategy (found by a search over random fragment strings).
MULTI_PASS = (
    '*sk-;}\n*api_keya@b.io;}"_@ ,==***://u:p@h=pwd=/4242 sk-Basic'
    " * Bearer ://u:p@hghp_*pwd=ghp_-----BEGIN PRIVATE KEY-----to"
    'ken@,}=Password=\n-=:=-----="_\'\'.,------4242 ""_sk-api_keypas'
    "sword'://AIza://u:p@h;Basic Bearer "
)

LABEL = MaskConfig(strategy="label")


def test_noise_that_needs_several_passes_still_settles_and_leaks_nothing() -> None:
    config = MaskConfig(strategy="partial")
    out = mask_text(MULTI_PASS, config=config)
    assert mask_text(out, config=config) == out
    assert "pwd=ghp_" not in out and "u:p@h=pwd" not in out


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("://u:pwd={x@h,y}a@b.io", "://u:<redacted:url_credentials>"),
        ("postgres://u:p@a@b@host/db", "postgres://u:<redacted:url_credentials>@host/db"),
        (
            "my_extremely_long_service_token=hunter2",
            "my_extremely_long_service_token=<redacted:assignment>",
        ),
        ('token="' + "word " * 12 + '"', 'token="<redacted:assignment>"'),
        ("mail ada@example.photography", "mail <redacted:email>"),
    ],
)
def test_long_parts_are_hidden_whole(text: str, expected: str) -> None:
    assert mask_text(text, config=LABEL) == expected


def test_a_custom_pattern_matching_empty_text_never_renames_a_card() -> None:
    config = MaskConfig(extra_patterns=(("p", "x*"),), strategy="label")
    assert mask_text("pay 4111 1111 1111 1111", config=config) == "pay <redacted:credit_card>"


def test_an_allowlisted_run_holding_two_cards_is_kept() -> None:
    run = "4111 1111 1111 1111 0000 0000 0004"
    assert mask_text(run, config=MaskConfig(allowlist=(run,))) == run
    assert mask_text(run) == "***"


def test_a_42_character_strategy_is_not_quoted_in_the_error() -> None:
    token = "ghp_" + "Q" * 36
    with pytest.raises(ValueError) as info:
        MaskConfig(strategy=token)
    assert token not in str(info.value)


def test_shared_objects_cost_their_size_not_their_unfolding() -> None:
    data: object = [{"token": "t", "note": "a@b.io"}]
    for _ in range(60):
        data = [data, data]
    start = time.perf_counter()
    out = mask(data)
    assert time.perf_counter() - start < 1.0
    for _ in range(60):
        assert isinstance(out, list)
        assert out[0] is out[1]
        out = out[0]
    assert out == [{"token": "***", "note": "***"}]


class _Fresh(Mapping[int, object]):
    """A mapping that builds a new value on every access, so ids get reused."""

    def __getitem__(self, key: int) -> object:
        return [f"row {key}", {"token": "t"}]

    def __iter__(self) -> Iterator[int]:
        return iter(range(6))

    def __len__(self) -> int:
        return 6


def test_values_built_on_access_are_never_confused() -> None:
    out = mask(_Fresh())
    assert out == {k: [f"row {k}", {"token": "***"}] for k in range(6)}
