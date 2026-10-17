"""Card numbers: the Luhn checksum and the documented test numbers of a processor."""

from __future__ import annotations

import random

import pytest

from secretmask import MaskConfig, mask_text
from secretmask._cards import find_cards, luhn_ok

from ._corpus import card

# Test card numbers published for integration testing by Stripe,
# https://docs.stripe.com/testing (fetched 2026-10-16). Public test values, not cards.
STRIPE_TEST_CARDS = [
    "4242424242424242",
    "4000056655665556",
    "5555555555554444",
    "2223003122003222",
    "378282246310005",
    "6011111111111117",
    "3056930009020004",
    "36227206271667",
    "3566002020360505",
    "6200000000000005",
]


def _reference_luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char) * (2 if index % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def test_luhn_matches_a_plain_reference_implementation() -> None:
    rng = random.Random(5)
    for _ in range(20_000):
        digits = "".join(rng.choice("0123456789") for _ in range(rng.randint(1, 24)))
        assert luhn_ok(digits) == _reference_luhn(digits), digits


@pytest.mark.parametrize("number", STRIPE_TEST_CARDS)
def test_documented_test_cards_are_hidden_in_every_layout(number: str) -> None:
    assert luhn_ok(number)
    spaced = " ".join(number[i : i + 4] for i in range(0, len(number), 4))
    dashed = spaced.replace(" ", "-")
    for layout in (number, spaced, dashed):
        assert mask_text(f"pay with {layout}, thanks") == "pay with ***, thanks"


@pytest.mark.parametrize("seed", range(30))
def test_generated_cards_of_every_length_are_found(seed: int) -> None:
    rng = random.Random(seed)
    for length in range(13, 20):
        number = card(rng, "4", length)
        assert list(find_cards(f"n {number} m")) == [(2, 2 + length)]
        broken = number[:-1] + str((int(number[-1]) + 1) % 10)
        assert list(find_cards(broken)) == []


def test_lengths_outside_thirteen_to_nineteen_are_not_cards() -> None:
    rng = random.Random(3)
    for length in (12, 20, 24):
        number = card(rng, "4", length)
        assert mask_text(number) == number


def test_card_masking_can_be_switched_off_and_allowlisted() -> None:
    number = "4242 4242 4242 4242"
    assert mask_text(number, config=MaskConfig(mask_credit_cards=False)) == number
    assert mask_text(number, config=MaskConfig(allowlist=(number,))) == number
    assert mask_text(number, config=MaskConfig(strategy="label")) == "<redacted:credit_card>"


def test_the_longest_card_from_the_first_group_is_taken() -> None:
    number = "4242424242424242"
    extra = next(f"{n:03d}" for n in range(1000) if luhn_ok(number + f"{n:03d}"))
    spaced = " ".join(number[i : i + 4] for i in range(0, 16, 4))
    # Both the 16 digits and the 19 digits pass Luhn: the longer reading wins.
    assert mask_text(f"pan {spaced} {extra} end") == "pan *** end"


def test_single_digit_groups_never_form_a_card() -> None:
    number = card(random.Random(9), "4", 16)
    spread = " ".join(number)
    assert luhn_ok(number)
    assert mask_text(spread) == spread
    assert mask_text("-".join(number)) == "-".join(number)


def test_a_number_before_the_card_is_kept_and_the_card_hidden_whole() -> None:
    rng = random.Random(11)
    for _ in range(300):
        number = card(rng, "4", 16)
        spaced = " ".join(number[i : i + 4] for i in range(0, 16, 4))
        for before in ("qty 197", "2026 589", "ref 12"):  # three digits are never a first group
            assert mask_text(f"{before} {spaced} ok") == f"{before} *** ok", (before, spaced)
        # A four-digit number just before the card may read as part of it: when two
        # readings overlap both are hidden, so no digit of the card shows.
        out = mask_text(f"id 1234 {spaced} ok")
        assert out in ("id 1234 *** ok", "id *** ok"), out


def test_grouped_numbers_must_follow_a_card_layout() -> None:
    assert mask_text("3782 822463 10005") == "***"  # 4-6-5
    assert mask_text("3056 930902 5904") == "***"  # 4-6-4
    assert mask_text("3622 7206 2716 67") == "***"  # 4-4-4-2
    assert mask_text("378 2822 4631 0005") == "378 2822 4631 0005"  # starts with three
    assert mask_text("4242 42424 2424242") == "4242 42424 2424242"  # a five in the middle


@pytest.mark.parametrize(
    "number",
    ["88762 3286 0129 0404", "0750 0201 0170 1887525", "1598 19072 36081", "1375 85847 19544"],
)
def test_luhn_valid_numbers_in_other_layouts_are_kept(number: str) -> None:
    assert luhn_ok(number.replace(" ", ""))
    assert mask_text(number) == number


def test_overlapping_readings_hide_every_digit_and_long_runs_hide_every_card() -> None:
    assert mask_text("9179 1044 839473 2969 0") == "***"
    run = "4242 4242 4242 4242 " * 40
    out = mask_text(run + "end")
    assert "4242" not in out and out.endswith("end")
