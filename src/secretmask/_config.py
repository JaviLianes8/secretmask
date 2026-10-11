"""Configuration for a masker: strategy, placeholder, patterns, keys, allowlist."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ._patterns import BUILTIN_KEYS, BUILTIN_PATTERNS
from ._strategy import Strategy


def _normalize_key(key: str) -> str:
    """Lower-case a key name and drop every non-alphanumeric character."""
    return re.sub(r"[^a-z0-9]+", "", key.lower())


@dataclass(frozen=True)
class MaskConfig:
    """How a :class:`~secretmask.SecretMask` redacts values.

    ``extra_patterns`` are ``(name, regex)`` pairs appended to the built-ins, and
    ``extra_keys`` are extra sensitive key names. Set ``use_builtin_patterns`` or
    ``use_builtin_keys`` to False to start from an empty set.

    ``strategy`` chooses how a secret is rendered: ``Strategy.FULL`` (the
    placeholder), ``Strategy.LABEL`` (``<redacted:jwt>``), ``Strategy.PARTIAL``
    (keep the last ``keep_last`` characters) or ``Strategy.HASH`` (a short
    deterministic ``<sha256:...>`` digest of ``hash_length`` hex characters). The
    older ``label=True`` flag still works and is the same as ``Strategy.LABEL``.

    ``allowlist`` holds exact strings that must never be masked, whether they are
    matched by a pattern, by the card scanner or as the value of a sensitive key.
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

    _patterns: tuple[tuple[str, re.Pattern[str]], ...] = field(init=False, repr=False)
    _keys: frozenset[str] = field(init=False, repr=False)
    _allow: frozenset[str] = field(init=False, repr=False)
    _strategy: Strategy = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.keep_last < 0:
            raise ValueError("keep_last must not be negative")
        if not 1 <= self.hash_length <= 64:
            raise ValueError("hash_length must be between 1 and 64")
        base_patterns = BUILTIN_PATTERNS if self.use_builtin_patterns else ()
        compiled = tuple(
            (name, re.compile(regex)) for name, regex in (*base_patterns, *self.extra_patterns)
        )
        base_keys = BUILTIN_KEYS if self.use_builtin_keys else ()
        keys = frozenset(_normalize_key(k) for k in (*base_keys, *self.extra_keys) if k)
        if self.strategy is not None:
            strategy = Strategy(self.strategy)
        elif self.label:
            strategy = Strategy.LABEL
        else:
            strategy = Strategy.FULL
        # Frozen dataclass: set the derived fields through object.__setattr__.
        object.__setattr__(self, "_patterns", compiled)
        object.__setattr__(self, "_keys", keys)
        object.__setattr__(self, "_allow", frozenset(self.allowlist))
        object.__setattr__(self, "_strategy", strategy)
