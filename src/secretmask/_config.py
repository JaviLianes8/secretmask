"""Configuration for a masker: strategy, placeholder, detectors, keys and allowlist."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ._keys import KeyMatcher, normalize_key
from ._patterns import BUILTIN_KEYS, BUILTIN_PATTERNS
from ._strategy import Strategy

_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_BUILTIN = tuple((name, re.compile(regex)) for name, regex in BUILTIN_PATTERNS)


def _preview(value: object) -> str:
    # Errors show short values only: a long one may be a secret pasted by mistake.
    if isinstance(value, int) and value.bit_length() > 64:
        return f"an integer of {value.bit_length()} bits"
    text = repr(value)
    return text if len(text) <= 24 else f"a value of {len(text)} characters"


def _strings(field_name: str, value: Any) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be a tuple of strings, got {type(value).__name__}")
    items = tuple(value)
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must hold strings, got {type(item).__name__}")
    return items


def _compile(pairs: Any) -> tuple[tuple[str, re.Pattern[str]], ...]:
    if isinstance(pairs, (str, bytes)) or not isinstance(pairs, Iterable):
        raise TypeError("extra_patterns must be a tuple of (name, regex) pairs")
    compiled = []
    for pair in pairs:
        if isinstance(pair, (str, bytes)) or not isinstance(pair, Sequence) or len(pair) != 2:
            raise TypeError("extra_patterns must hold (name, regex) pairs")
        name, regex = pair
        if not (isinstance(name, str) and isinstance(regex, str)):
            raise TypeError("a (name, regex) pair must hold two strings")
        if not _NAME.fullmatch(name):
            raise ValueError(f"pattern name must be 1 to 64 of A-Z a-z 0-9 _ . -: {_preview(name)}")
        try:
            compiled.append((name, re.compile(regex)))
        except re.error as error:
            raise ValueError(f"pattern {name!r} is not a valid regex: {error.msg}") from None
    return tuple(compiled)


def _check_int(name: str, value: object, low: int, high: int | None) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < low or (high is not None and value > high):
        bound = f"between {low} and {high}" if high is not None else f"at least {low}"
        raise ValueError(f"{name} must be {bound}, got {_preview(value)}")


def _check_bool(name: str, value: object) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a bool, got {type(value).__name__}")


def _strategy(value: object, label: bool) -> Strategy:
    if value is None:
        return Strategy.LABEL if label else Strategy.FULL
    if not isinstance(value, str):
        raise TypeError(f"strategy must be a Strategy or str, got {type(value).__name__}")
    try:
        return Strategy(value)
    except ValueError:
        choices = ", ".join(s.value for s in Strategy)
        raise ValueError(f"strategy must be one of {choices}, got {_preview(value)}") from None


@dataclass(frozen=True)
class MaskConfig:
    """How a :class:`SecretMask` finds and renders secrets.

    ``extra_patterns`` are ``(name, regex)`` pairs tried after the built-in
    detectors, ``extra_keys`` are extra sensitive key names and ``allowlist``
    holds exact values that are never masked. ``use_builtin_patterns``,
    ``use_builtin_keys`` and ``mask_credit_cards`` switch the built-ins off.
    ``strategy`` picks the rendering (see :class:`Strategy`); ``label=True`` is
    the same as ``strategy="label"``. ``keep_last`` is used by ``partial``,
    ``hash_length`` and ``hash_key`` by ``hash``.

    Wrong types raise :class:`TypeError` and bad values :class:`ValueError`, when
    the config is built; a list where a tuple is expected is accepted.

    >>> from secretmask import MaskConfig, mask_text
    >>> config = MaskConfig(extra_patterns=(("ticket", r"TCK-\\d{4}"),), strategy="label")
    >>> mask_text("see TCK-1234", config=config)
    'see <redacted:ticket>'
    >>> MaskConfig(keep_last=-1)
    Traceback (most recent call last):
    ...
    ValueError: keep_last must be at least 0, got -1
    """

    placeholder: str = "***"
    extra_patterns: tuple[tuple[str, str], ...] = ()
    extra_keys: tuple[str, ...] = ()
    allowlist: tuple[str, ...] = ()
    use_builtin_patterns: bool = True
    use_builtin_keys: bool = True
    mask_credit_cards: bool = True
    label: bool = False
    strategy: Strategy | str | None = None
    keep_last: int = 4
    hash_length: int = 8
    hash_key: str | bytes | None = field(default=None, repr=False)

    _patterns: tuple[tuple[str, re.Pattern[str]], ...] = field(
        init=False, repr=False, compare=False
    )
    _keys: KeyMatcher = field(init=False, repr=False, compare=False)
    _allow: frozenset[str] = field(init=False, repr=False, compare=False)
    _strategy: Strategy = field(init=False, repr=False, compare=False)
    _hash_key: bytes | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.placeholder, str):
            raise TypeError(f"placeholder must be a str, got {type(self.placeholder).__name__}")
        for name in ("use_builtin_patterns", "use_builtin_keys", "mask_credit_cards", "label"):
            _check_bool(name, getattr(self, name))
        _check_int("keep_last", self.keep_last, 0, None)
        _check_int("hash_length", self.hash_length, 1, 64)
        key = self.hash_key
        if key is not None and not isinstance(key, (str, bytes)):
            raise TypeError(f"hash_key must be str or bytes, got {type(key).__name__}")
        extra = _compile(self.extra_patterns)
        keys = _strings("extra_keys", self.extra_keys)
        allow = _strings("allowlist", self.allowlist)
        names = (*BUILTIN_KEYS, *keys) if self.use_builtin_keys else keys
        # Frozen dataclass: normalised and derived fields go through object.__setattr__.
        setter = object.__setattr__
        setter(self, "extra_patterns", tuple((n, r.pattern) for n, r in extra))
        setter(self, "extra_keys", keys)
        setter(self, "allowlist", allow)
        setter(self, "_patterns", (_BUILTIN if self.use_builtin_patterns else ()) + extra)
        setter(self, "_keys", KeyMatcher(frozenset(normalize_key(k) for k in names)))
        setter(self, "_allow", frozenset(allow))
        setter(self, "_strategy", _strategy(self.strategy, self.label))
        setter(self, "_hash_key", key.encode("utf-8") if isinstance(key, str) else key)
