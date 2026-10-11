"""The masker: redact secrets in strings and recursively in nested data."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from typing import Any

from ._config import MaskConfig, _normalize_key
from ._patterns import _CARD_CANDIDATE, luhn_ok
from ._strategy import Strategy, render

_CARD_RE = re.compile(_CARD_CANDIDATE)


class SecretMask:
    """A reusable masker built from a :class:`MaskConfig`.

    Build one and keep it: the patterns are compiled once. Every method returns a
    redacted copy and never mutates its input, and masking is idempotent, so
    masking an already-masked value changes nothing.
    """

    def __init__(self, config: MaskConfig | None = None) -> None:
        self._config = config or MaskConfig()

    def mask_text(self, text: str) -> str:
        """Redact every known secret pattern found inside a single string."""
        result = text
        for name, regex in self._config._patterns:
            result = regex.sub(self._replacer(name), result)
        if self._config.mask_credit_cards:
            result = self._mask_cards(result)
        return result

    def mask(self, value: Any) -> Any:
        """Redact a value recursively.

        Strings are pattern-redacted. In a mapping, the value of any sensitive key
        is replaced according to the strategy; other values are masked in turn.
        Lists and tuples are walked element by element. Anything else is returned
        unchanged.
        """
        if isinstance(value, Mapping):
            return {
                key: (
                    self._mask_key_value(str(key), item)
                    if self._is_sensitive_key(key)
                    else self.mask(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, str):
            return self.mask_text(value)
        if isinstance(value, (list, tuple)):
            masked = [self.mask(item) for item in value]
            return tuple(masked) if isinstance(value, tuple) else masked
        return value

    def mask_json(self, text: str) -> str:
        """Parse a JSON document, mask it by structure, and re-serialise it.

        Raises :class:`ValueError` if ``text`` is not valid JSON.
        """
        return json.dumps(self.mask(json.loads(text)), ensure_ascii=False)

    def _is_sensitive_key(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        normalized = _normalize_key(key)
        return any(name in normalized for name in self._config._keys)

    def _mask_key_value(self, key: str, value: Any) -> Any:
        if isinstance(value, str) and value in self._config._allow:
            return value
        strategy = self._config._strategy
        if strategy in (Strategy.PARTIAL, Strategy.HASH) and isinstance(value, str):
            return self._render(strategy, value, key)
        if strategy is Strategy.LABEL:
            return f"<redacted:{key}>"
        return self._config.placeholder

    def _render(self, strategy: Strategy, secret: str, name: str) -> str:
        return render(
            strategy,
            secret,
            name,
            placeholder=self._config.placeholder,
            keep_last=self._config.keep_last,
            hash_length=self._config.hash_length,
        )

    def _replacer(self, name: str) -> Callable[[re.Match[str]], str]:
        strategy = self._config._strategy
        allow = self._config._allow

        def repl(match: re.Match[str]) -> str:
            if "s" in match.re.groupindex:
                whole = match.group(0)
                secret = match.group("s")
                if secret in allow:
                    return whole
                start = match.start("s") - match.start()
                end = match.end("s") - match.start()
                return whole[:start] + self._render(strategy, secret, name) + whole[end:]
            secret = match.group(0)
            if secret in allow:
                return secret
            return self._render(strategy, secret, name)

        return repl

    def _mask_cards(self, text: str) -> str:
        strategy = self._config._strategy
        allow = self._config._allow

        def repl(match: re.Match[str]) -> str:
            whole = match.group(0)
            digits = re.sub(r"[^0-9]", "", whole)
            if 13 <= len(digits) <= 19 and luhn_ok(digits) and whole not in allow:
                return self._render(strategy, whole, "credit_card")
            return whole

        return _CARD_RE.sub(repl, text)


_default = SecretMask()


def mask(value: Any, *, config: MaskConfig | None = None) -> Any:
    """Redact a value recursively using the default or a given configuration."""
    masker = SecretMask(config) if config is not None else _default
    return masker.mask(value)


def mask_text(text: str, *, config: MaskConfig | None = None) -> str:
    """Redact every known secret pattern inside a single string."""
    masker = SecretMask(config) if config is not None else _default
    return masker.mask_text(text)


def mask_json(text: str, *, config: MaskConfig | None = None) -> str:
    """Mask a JSON document by structure and return masked JSON.

    Raises :class:`ValueError` if ``text`` is not valid JSON.
    """
    masker = SecretMask(config) if config is not None else _default
    return masker.mask_json(text)


__all__ = ["SecretMask", "mask", "mask_json", "mask_text"]
