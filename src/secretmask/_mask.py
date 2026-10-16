"""The masker: redact secrets in strings and, recursively, in nested data."""

from __future__ import annotations

import json
from typing import Any

from ._config import MaskConfig
from ._scan import mask_string
from ._strategy import Strategy, render
from ._walk import walk


class SecretMask:
    """A reusable masker built from a :class:`MaskConfig`.

    Build one and keep it: the detectors are compiled once, when the config is
    built. Every method returns a masked copy and never changes its input, and
    masking is idempotent for the built-in detectors: masking a masked value
    changes nothing. A masker holds no mutable state that affects results, so
    one instance can be shared between threads.

    >>> from secretmask import MaskConfig, SecretMask
    >>> masker = SecretMask(MaskConfig(strategy="label"))
    >>> masker.mask_text("mail ada@example.com")
    'mail <redacted:email>'
    >>> masker.mask({"token": "t0ps3cret", "user": "ada"})
    {'token': '<redacted:token>', 'user': 'ada'}
    >>> masker.config.strategy
    'label'
    """

    def __init__(self, config: MaskConfig | None = None) -> None:
        if config is not None and not isinstance(config, MaskConfig):
            raise TypeError(f"config must be a MaskConfig, got {type(config).__name__}")
        self._config = config if config is not None else MaskConfig()

    @property
    def config(self) -> MaskConfig:
        """The configuration this masker was built from."""
        return self._config

    def __repr__(self) -> str:
        return f"SecretMask({self._config!r})"

    def mask_text(self, text: str) -> str:
        """Redact every detected secret inside one string.

        >>> SecretMask().mask_text("Authorization: Bearer abc123def456ghi")
        'Authorization: Bearer ***'
        """
        if not isinstance(text, str):
            raise TypeError(f"mask_text expects a str, got {type(text).__name__}")
        config = self._config
        return mask_string(
            text,
            config._patterns,
            cards=config.mask_credit_cards,
            allow=config._allow,
            placeholder=config.placeholder,
            render=self._render,
        )

    def mask(self, value: Any) -> Any:
        """Redact a value recursively and return the masked copy.

        Strings are scanned with :meth:`mask_text`. In a mapping, the value of a
        sensitive key is replaced as a whole (a nested value included) and other
        values are masked in turn; mappings come back as ``dict``, lists as
        ``list`` and tuples as plain ``tuple``. Any other value is returned as it
        is. A structure that contains itself raises :class:`ValueError`.

        >>> SecretMask().mask({"password": "hunter2", "note": ["mail ada@example.com", 7]})
        {'password': '***', 'note': ['mail ***', 7]}
        """
        return walk(value, leaf=self.mask_text, sensitive=self._config._keys, hide=self._hide)

    def mask_json(self, text: str) -> str:
        """Parse a JSON document, mask it by structure, and serialise it again.

        The output is compact JSON on one line with non-ASCII text kept as is.
        Raises :class:`ValueError` if ``text`` is not valid JSON.

        >>> SecretMask().mask_json('{"api_key": "k-123", "user": "ada"}')
        '{"api_key": "***", "user": "ada"}'
        """
        if not isinstance(text, str):
            raise TypeError(f"mask_json expects a str, got {type(text).__name__}")
        try:
            data = json.loads(text)
        except RecursionError:
            raise ValueError("JSON document is nested too deeply") from None
        return json.dumps(self.mask(data), ensure_ascii=False)

    def _hide(self, key: str, value: Any) -> Any:
        if isinstance(value, str) and value in self._config._allow:
            return value
        strategy = self._config._strategy
        if strategy in (Strategy.PARTIAL, Strategy.HASH) and isinstance(value, str):
            return self._render(value, key)
        if strategy is Strategy.LABEL:
            return f"<redacted:{key}>"
        return self._config.placeholder

    def _render(self, secret: str, name: str) -> str:
        config = self._config
        return render(
            config._strategy,
            secret,
            name,
            placeholder=config.placeholder,
            keep_last=config.keep_last,
            hash_length=config.hash_length,
            hash_key=config._hash_key,
        )


_default = SecretMask()


def _masker(config: MaskConfig | None) -> SecretMask:
    return _default if config is None else SecretMask(config)


def mask(value: Any, *, config: MaskConfig | None = None) -> Any:
    """Redact a value recursively; see :meth:`SecretMask.mask`.

    >>> from secretmask import mask
    >>> mask({"user": "ada", "db_password": "hunter2", "tags": ("a@b.io", 1)})
    {'user': 'ada', 'db_password': '***', 'tags': ('***', 1)}
    """
    return _masker(config).mask(value)


def mask_text(text: str, *, config: MaskConfig | None = None) -> str:
    """Redact every detected secret inside one string; see :meth:`SecretMask.mask_text`.

    >>> from secretmask import mask_text
    >>> mask_text("card 4242 4242 4242 4242 exp 12/34, mail ada@example.com")
    'card *** exp 12/34, mail ***'
    """
    return _masker(config).mask_text(text)


def mask_json(text: str, *, config: MaskConfig | None = None) -> str:
    """Mask a JSON document by structure; see :meth:`SecretMask.mask_json`.

    >>> from secretmask import mask_json
    >>> mask_json('{"password": "p", "note": "ping a@b.io"}')
    '{"password": "***", "note": "ping ***"}'
    """
    return _masker(config).mask_json(text)
