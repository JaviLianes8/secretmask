"""Hostile input: the work stays linear, nothing crashes, nothing hangs."""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from secretmask import MaskConfig, Strategy, mask, mask_json, mask_text

# Each input repeats the start of a detector without ever completing it, or packs
# many near-matches together: the shapes that make a backtracking regex quadratic.
HOSTILE: dict[str, Callable[[int], str]] = {
    "pem_begin": lambda n: "-----BEGIN PRIVATE KEY-----" * (n // 27),
    "pem_body": lambda n: "-----BEGIN PRIVATE KEY-----\n" + "A-" * (n // 2),
    "jwt_heads": lambda n: "eyJ" * (n // 3),
    "jwt_dots": lambda n: "eyJa." * (n // 5),
    "github": lambda n: "ghp_" * (n // 4),
    "github_jwt": lambda n: "ghs_1_eyJ" * (n // 9),
    "openai": lambda n: "sk-" * (n // 3),
    "aws": lambda n: "AKIA" * (n // 4),
    "slack": lambda n: "xoxb-" * (n // 5),
    "slack_hook": lambda n: "hooks.slack.com/services/" * (n // 25),
    "google": lambda n: "AIza" * (n // 4),
    "url": lambda n: "://a:" * (n // 5),
    "url_at": lambda n: "://:" + "@" * n,
    "conn": lambda n: 'password="' * (n // 10),
    "conn_brace": lambda n: "pwd={" * (n // 5),
    "basic": lambda n: "Authorization: Basic " * (n // 21),
    "bearer": lambda n: "Bearer " * (n // 7),
    "assign_long_key": lambda n: "a_" * (n // 2) + "password",
    "assign_keys": lambda n: "x.password" * (n // 10),
    "assign_quotes": lambda n: "token='" * (n // 7),
    "email_at": lambda n: "a@" * (n // 2),
    "email_dots": lambda n: "a." * (n // 2) + "@",
    "cards_small": lambda n: "1 " * (n // 2),
    "cards_groups": lambda n: "111 " * (n // 4),
    "cards_dashes": lambda n: "4111-" * (n // 5),
    "digits": lambda n: "4" * n,
    "letters": lambda n: "a" * n,
    "newlines": lambda n: "\n" * n,
    "masks": lambda n: "token=***" * (n // 9),
}


def _seconds(text: str, config: MaskConfig | None = None) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        mask_text(text, config=config)
        best = min(best, time.perf_counter() - start)
    return best


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_work_grows_linearly(name: str) -> None:
    make = HOSTILE[name]
    small, large = _seconds(make(100_000)), _seconds(make(400_000))
    assert large < 4.0, f"{name}: {large:.2f} s for 400 kB"
    # Four times the input may cost at most about four times the time (plus noise).
    assert large < 6 * small + 0.05, f"{name}: {small:.3f} s -> {large:.3f} s"


@pytest.mark.parametrize("strategy", list(Strategy))
def test_every_strategy_survives_a_megabyte_of_mixed_secrets(strategy: Strategy) -> None:
    line = "user=ada password=hunter2 Bearer abcdefgh12 a@b.io 4242 4242 4242 4242\n"
    text = line * (1_000_000 // len(line))
    start = time.perf_counter()
    out = mask_text(text, config=MaskConfig(strategy=strategy))
    assert time.perf_counter() - start < 10.0
    assert "hunter2" not in out and "a@b.io" not in out


def test_large_flat_and_wide_structures() -> None:
    data = {f"key{i}": f"a{i}@b.io" for i in range(50_000)}
    data["password"] = "p"
    out = mask(data)
    assert out["key7"] == "***" and out["password"] == "***" and len(out) == 50_001
    big = mask_json('{"a": [' + ",".join(['"x"'] * 100_000) + "]}")
    assert big.count('"x"') == 100_000


def test_odd_strings_never_crash() -> None:
    lone_surrogate = chr(0xD800)
    odd = [
        lone_surrogate + " password=x",
        chr(0) * 10,
        chr(0x202E) + "password=x",
        chr(0xFEFF) + "a@b.io",
        chr(0x1D7D2) * 16,
    ]
    for text in odd:
        out = mask_text(text)
        assert isinstance(out, str)
        assert mask_text(out) == out
    assert mask_text(odd[0]) == lone_surrogate + " password=***"
