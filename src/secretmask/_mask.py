"""The masker: redact secrets in strings and recursively in nested data."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from ._config import MaskConfig, _normalize_key
from ._patterns import _CARD_CANDIDATE, luhn_ok

_CARD_RE = re.compile(_CARD_CANDIDATE)


class SecretMask:
    """A reusable masker built from a :class:`MaskConfig`.

    Build one and keep it: the patterns are compiled once. Both methods return a
    redacted copy and never mutate their input.
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
        is replaced wholesale; other values are masked in turn. Lists and tuples
        are walked element by element. Anything else is returned unchanged.
        """
        if isinstance(value, Mapping):
            return {
                key: (
                    self._placeholder_for(str(key))
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

    def _is_sensitive_key(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        normalized = _normalize_key(key)
        return any(name in normalized for name in self._config._keys)

    def _placeholder_for(self, name: str) -> str:
        if self._config.label:
            return f"<redacted:{name}>"
        return self._config.placeholder

    def _replacer(self, name: str) -> Callable[[re.Match[str]], str]:
        placeholder = self._placeholder_for(name)

        def repl(match: re.Match[str]) -> str:
            if "s" in match.re.groupindex:
                whole = match.group(0)
                start = match.start("s") - match.start()
                end = match.end("s") - match.start()
                return whole[:start] + placeholder + whole[end:]
            return placeholder

        return repl

    def _mask_cards(self, text: str) -> str:
        placeholder = self._placeholder_for("credit_card")

        def repl(match: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", match.group(0))
            if 13 <= len(digits) <= 19 and luhn_ok(digits):
                return placeholder
            return match.group(0)

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


# Sequence is imported for the public type intent even though list/tuple are
# matched directly above; keep the import meaningful for readers and linters.
__all__ = ["SecretMask", "mask", "mask_text"]
