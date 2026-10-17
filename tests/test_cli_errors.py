"""Command-line error messages: nothing typed or read ever reaches standard error."""

from __future__ import annotations

from .test_cli import _run


def test_error_messages_never_repeat_a_secret_or_a_long_value() -> None:
    token = "ghp_" + "Q" * 36
    cases = [
        ["--token=" + token],
        ["-" + token],
        ["--strategy", token, "x"],
        ["--keep-last", token, "x"],
        ["--file", "missing-" + "x" * 100],
        ["--pattern", "n=(" + token, "x"],
    ]
    for args in cases:
        result = _run(*args)
        assert result.returncode in (1, 2), args
        assert token.encode() not in result.stderr, args
        assert b"x" * 50 not in result.stderr, args


def test_no_typed_value_reaches_standard_error() -> None:
    secret = "hunter2pwLongEnoughToSee"
    cases = [
        ["-X" + secret],
        ["--strategy", secret, "x"],
        ["--keep-last", secret, "x"],
        ["--ke=" + secret],
        ["--json=" + secret],
        ["--no-cards=" + secret],
        ["--ke=a " + secret],
        ["--ke=a" + chr(9) + secret],
        ["--p=x " + secret],
        ["--ke=" + secret + "=x"],
        ["--json=it's" + secret],
        ["--strategy", "it's" + secret, "x"],
        ["--keep-last", "it's" + secret, "x"],
        ["--hash-length=it's" + secret, "x"],
        ["--strategy", "x: " + secret, "x"],
        ["--keep-last", secret + ": b", "x"],
    ]
    for args in cases:
        result = _run(*args)
        assert result.returncode == 2, args
        for piece in (secret, secret[1:], secret[:-1], "hunter2"):
            assert piece.encode() not in result.stderr, (args, piece)
    many = _run("a", "b", "c")
    assert b"2 unrecognized argument(s)" in many.stderr


def test_errors_of_ours_are_masked_too() -> None:
    result = _run("--file", "pwd=hunter2x")
    assert result.returncode == 1
    assert b"hunter2x" not in result.stderr and b"pwd=***" in result.stderr


def test_long_quoted_values_in_errors_are_described_by_length() -> None:
    short = _run("--file", "m" * 24)
    long = _run("--file", "m" * 25)
    assert b"m" * 24 in short.stderr
    assert b"m" * 25 not in long.stderr and b"a value of 25 characters" in long.stderr


def test_a_missing_option_value_is_named_as_such() -> None:
    result = _run("--keep-last")
    assert result.returncode == 2
    assert b"argument --keep-last: expected one argument" in result.stderr
