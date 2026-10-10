"""Configuration for a masker: placeholder, extra patterns and extra key names."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ._patterns import BUILTIN_KEYS, BUILTIN_PATTERNS


def _normalize_key(key: str) -> str:
    """Lower-case a key name and drop every non-alphanumeric character."""
    return re.sub(r"[^a-z0-9]+", "", key.lower())


@dataclass(frozen=True)
class MaskConfig:
    """How a :class:`~secretmask.SecretMask` redacts values.

    ``extra_patterns`` are ``(name, regex)`` pairs appended to the built-ins, and
    ``extra_keys`` are extra sensitive key names. Set ``use_builtin_patterns`` or
    ``use_builtin_keys`` to False to start from an empty set. With ``label`` on,
    each redaction shows what it hid, for example ``<redacted:jwt>``.
    """

    placeholder: str = "***"
    extra_patterns: tuple[tuple[str, str], ...] = ()
    extra_keys: tuple[str, ...] = ()
    use_builtin_patterns: bool = True
    use_builtin_keys: bool = True
    mask_credit_cards: bool = True
    label: bool = False

    _patterns: tuple[tuple[str, re.Pattern[str]], ...] = field(init=False, repr=False)
    _keys: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        base_patterns = BUILTIN_PATTERNS if self.use_builtin_patterns else ()
        compiled = tuple(
            (name, re.compile(regex)) for name, regex in (*base_patterns, *self.extra_patterns)
        )
        base_keys = BUILTIN_KEYS if self.use_builtin_keys else ()
        keys = frozenset(_normalize_key(k) for k in (*base_keys, *self.extra_keys) if k)
        # Frozen dataclass: set the derived fields through object.__setattr__.
        object.__setattr__(self, "_patterns", compiled)
        object.__setattr__(self, "_keys", keys)
