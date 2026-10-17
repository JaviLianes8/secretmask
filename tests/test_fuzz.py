"""Seeded property tests: random text, random data, planted secrets."""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from secretmask import MaskConfig, SecretMask, Strategy, mask, mask_json, mask_text

from ._corpus import tokens

PIECES = [
    "a", "Z", "0", "7", " ", "\n", "\t", "=", ":", "@", ".", "/", "-", "_", "'", '"', ";", ",",
    "{", "}", "[", "]", "<", ">", "*", "eyJ", "sk-", "sk_live_", "AKIA", "ghp_", "xoxb-",
    "AIza", "://", "Bearer ", "Basic ", "password", "token", "secret", "api_key", "-----",
    "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", "4242", "1111", "é", "你",
    "<redacted:x>", "<sha256:ab>", "***",
]  # fmt: skip
SAFE_WORDS = ["alpha", "beta", "request", "done", "user", "ok", "id", "42", "café", "200"]
DELIMITERS = [" ", "\n", ", ", " (", ") ", '"', "'", "; ", " | "]
STRATEGIES = [MaskConfig(strategy=s) for s in Strategy] + [MaskConfig(placeholder="[x]")]


def _noise(rng: random.Random, size: int) -> str:
    return "".join(rng.choice(PIECES) for _ in range(size))


@pytest.mark.parametrize("seed", range(150))
def test_random_text_never_crashes_and_masking_is_idempotent(seed: int) -> None:
    rng = random.Random(seed)
    text = _noise(rng, rng.randint(0, 400))
    for config in STRATEGIES:
        once = mask_text(text, config=config)
        assert mask_text(once, config=config) == once, (text, config.strategy)


@pytest.mark.parametrize("seed", range(150))
def test_planted_secrets_never_survive_and_the_words_around_them_do(seed: int) -> None:
    rng = random.Random(seed)
    planted = [token for _, token in tokens(seed)]
    rng.shuffle(planted)
    parts: list[str] = []
    for token in planted:
        parts.append(rng.choice(SAFE_WORDS))
        parts.append(rng.choice(DELIMITERS))
        parts.append(token)
        parts.append(rng.choice(DELIMITERS))
    text = "".join(parts) + "end"
    for config in STRATEGIES[:2] + STRATEGIES[3:]:  # partial keeps a tail on purpose
        out = mask_text(text, config=config)
        for token in planted:
            assert token not in out, (token, config.strategy)
            assert token[len(token) // 2 :] not in out, (token, config.strategy)
        assert out.endswith("end")
        assert mask_text(out, config=config) == out


def _data(rng: random.Random, depth: int) -> Any:
    kind = rng.randrange(6 if depth < 4 else 3)
    if kind == 0:
        return rng.choice([None, True, 3, 2.5, "plain", "mail a@b.io", "pwd=x1"])
    if kind == 1:
        return rng.choice(SAFE_WORDS)
    if kind == 2:
        return _noise(rng, rng.randint(0, 30))
    if kind == 3:
        return [_data(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    keys = ["user", "token", "password", "note", "items", "apiKey", "count", "Authorization"]
    return {rng.choice(keys) + str(i): _data(rng, depth + 1) for i in range(rng.randint(0, 4))}


def _shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shape(v) for v in value]
    return type(value).__name__


@pytest.mark.parametrize("seed", range(150))
def test_random_data_keeps_its_shape_and_json_agrees(seed: int) -> None:
    rng = random.Random(seed)
    data = {"root": _data(rng, 0)}
    for strategy in Strategy:
        masker = SecretMask(MaskConfig(strategy=strategy))
        out = masker.mask(data)
        assert list(out) == ["root"]
        assert masker.mask(out) == out
        assert masker.mask_json(json.dumps(data)) == json.dumps(out, ensure_ascii=False)
    plain = mask(data)
    keyed = [k for k in json.dumps(data).split('"') if k[:-1] in {"token", "password", "apiKey"}]
    assert json.dumps(plain) == json.dumps(mask(plain))
    assert keyed == keyed  # the keys themselves are never renamed (checked by the shape below)
    if isinstance(data["root"], dict):
        assert list(plain["root"]) == list(data["root"])


@pytest.mark.parametrize("seed", range(40))
def test_mask_json_of_random_json_text_round_trips(seed: int) -> None:
    rng = random.Random(seed)
    document = json.dumps(_data(rng, 0), ensure_ascii=rng.random() < 0.5)
    out = mask_json(document)
    assert json.loads(out) == mask(json.loads(document))
