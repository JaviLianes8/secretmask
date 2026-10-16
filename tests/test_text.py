"""Masking free text: one pass, overlaps, idempotence, allowlist and Unicode."""

from __future__ import annotations

import pytest

from secretmask import MaskConfig, SecretMask, Strategy, mask, mask_text

BLOB = (
    "user=ada password=hunter2 Bearer abc123def456ghi mail me@x.io "
    "key AKIAIOSFODNN7EXAMPLE card 4242 4242 4242 4242 url https://u:pw@h/x"
)


@pytest.mark.parametrize("strategy", list(Strategy))
@pytest.mark.parametrize("placeholder", ["***", "[hidden]", "<gone>", "REDACTED", "x"])
def test_masking_twice_changes_nothing(strategy: Strategy, placeholder: str) -> None:
    masker = SecretMask(MaskConfig(strategy=strategy, placeholder=placeholder))
    once = masker.mask_text(BLOB)
    for secret in (
        "hunter2",
        "abc123def456ghi",
        "me@x.io",
        "AKIAIOSFODNN7EXAMPLE",
        "4242 4242",
        ":pw@",
    ):
        assert secret not in once
    assert masker.mask_text(once) == once
    data = {"password": "p", "log": BLOB}
    assert masker.mask(masker.mask(data)) == masker.mask(data)


def test_each_secret_is_replaced_once_even_when_detectors_overlap() -> None:
    label = MaskConfig(strategy="label")
    assert mask_text("token=AIza" + "d" * 35, config=label) == "token=<redacted:google_api_key>"
    assert mask_text("password=a@b.io", config=label) == "password=<redacted:connection_string>"
    assert mask_text("x [hidden] y", config=MaskConfig(placeholder="[hidden]")) == "x [hidden] y"


def test_a_secret_that_starts_with_the_placeholder_is_still_hidden() -> None:
    assert mask_text("password=***hunter2") == "password=***"
    assert mask_text("token=<redacted:x>tail") == "token=***"


def test_the_allowlist_is_exact_and_blocks_later_detectors() -> None:
    config = MaskConfig(allowlist=("a@b.io", "keepme"))
    assert mask_text("to a@b.io and c@d.io", config=config) == "to a@b.io and ***"
    assert mask_text("password=keepme", config=config) == "password=keepme"
    assert mask_text("password=keepme2", config=config) == "password=***"
    assert mask({"secret": "keepme", "token": "x"}, config=config) == {
        "secret": "keepme",
        "token": "***",
    }


def test_adjacent_and_repeated_secrets_are_all_hidden() -> None:
    assert mask_text("a@b.io c@d.io,e@f.io") == "*** ***,***"
    assert mask_text("Bearer abcdefgh1\nBearer abcdefgh2") == "Bearer ***\nBearer ***"


def test_text_without_secrets_is_returned_unchanged() -> None:
    for text in (
        "",
        "plain words",
        "café 你好 " + chr(0x0660) + chr(0x0661) + " ok",
        "\x00\x01\ud800 raw",
    ):
        assert mask_text(text) == text


def test_surrounding_unicode_survives_and_lines_keep_their_endings() -> None:
    text = "café ✓ token=s3cr3t\r\nnext 你好 a@b.io\n"
    assert mask_text(text) == "café ✓ token=***\r\nnext 你好 ***\n"
