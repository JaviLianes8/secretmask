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
