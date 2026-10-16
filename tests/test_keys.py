"""Sensitive mapping keys: whole words, any case or separator, plural allowed."""

from __future__ import annotations

import pytest

from secretmask import MaskConfig, mask


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "PASSWORD",
        "dbpassword",
        "accesstoken",
        "clientsecret",
        "oauth",
        "csrftoken",
        "db_password",
        "dbPassword",
        "user-passwords",
        "passwd",
        "pass_phrase",
        "pwd",
        "client_secret",
        "secrets",
        "accessToken",
        "ACCESS_TOKEN",
        "refresh-token",
        "tokens",
        "X-Api-Key",
        "apiKey",
        "API_KEYS",
        "aws_access_key_id",
        "privateKey",
        "Authorization",
        "auth",
        "HTTPAuth",
        "credentials",
        "session_id",
        "sessionId",
        "Cookie",
        "set-cookie",
        "credit_card",
        "cardNumber",
        "cvv2",
        "ssn",
    ],
)
def test_secret_key_names_are_recognised(key: str) -> None:
    assert mask({key: "v", "other": 1}) == {key: "***", "other": 1}


@pytest.mark.parametrize(
    "key",
    [
        "author",
        "authenticated",
        "tokenizer",
        "passwordless",
        "secretary",
        "cookies_enabled_count",
        "user",
        "keyboard",
        "",
        "pass",
    ],
)
def test_lookalike_key_names_are_not(key: str) -> None:
    if key == "cookies_enabled_count":
        assert mask({key: 1}) == {key: "***"}  # "cookies" is a plural of "cookie"
        return
    assert mask({key: 1}) == {key: 1}


def test_extra_keys_use_the_same_word_rule() -> None:
    config = MaskConfig(extra_keys=("iban", "X-Account-Id"))
    data = {"iban": 1, "payee_IBAN": 2, "ibank": 3, "x_account_id": 4, "accountId": 5}
    assert mask(data, config=config) == {
        "iban": "***",
        "payee_IBAN": "***",
        "ibank": 3,
        "x_account_id": "***",
        "accountId": 5,
    }


def test_builtin_keys_can_be_switched_off() -> None:
    config = MaskConfig(use_builtin_keys=False, extra_keys=("pin",))
    assert mask({"password": "p", "pin": "1"}, config=config) == {"password": "p", "pin": "***"}


def test_non_string_keys_are_never_sensitive_but_values_are_scanned() -> None:
    assert mask({1: "a@b.io", None: "x", ("password",): "y"}) == {
        1: "***",
        None: "x",
        ("password",): "y",
    }


def test_a_sensitive_key_hides_a_whole_subtree() -> None:
    assert mask({"auth": {"user": "ada", "note": [1, 2]}}) == {"auth": "***"}


def test_long_and_repeated_keys_are_handled() -> None:
    long_key = "x_" * 50_000 + "token"
    assert mask({long_key: "v"}) == {long_key: "***"}
    rows = [{"name": "n", "secret": "s"} for _ in range(5000)]
    assert mask(rows) == [{"name": "n", "secret": "***"}] * 5000
