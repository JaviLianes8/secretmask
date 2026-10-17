"""Redaction strategies: how a detected secret is turned into its masked form."""

from __future__ import annotations

import hashlib
import hmac
import re
from enum import Enum

_PARTIAL_FILL = "*"

# A token this module itself produces. Re-rendering one returns it unchanged, so
# masking an already-masked string is a no-op (idempotence), even for HASH, whose
# digest would otherwise be hashed again into a different value.
_MASKED_TOKEN = re.compile(r"<redacted:[^<>\s]*>|<sha256:[0-9a-f]{1,64}>")


class Strategy(str, Enum):
    """How a detected secret is rendered once it has been found.

    - ``FULL`` replaces the secret with the configured placeholder.
    - ``LABEL`` names the detector or key, for example ``<redacted:jwt>``.
    - ``PARTIAL`` keeps the last ``keep_last`` characters and masks the rest,
      for example ``***********6ghi``; a secret no longer than ``keep_last`` is
      masked in full so nothing is ever revealed outright.
    - ``HASH`` replaces the secret with a short SHA-256 digest such as
      ``<sha256:ab12cd34>``, so equal secrets can be correlated across lines.
      Set ``MaskConfig.hash_key`` to use a keyed HMAC: a plain digest of a short
      or guessable secret (a password) can be reversed by trying candidates.

    It is a :class:`str` enum, so ``"partial"`` and ``Strategy.PARTIAL`` are
    interchangeable and it serialises as plain text.

    >>> Strategy("partial") is Strategy.PARTIAL
    True
    >>> [s.value for s in Strategy]
    ['full', 'label', 'partial', 'hash']
    >>> Strategy.HASH == "hash"
    True
    """

    FULL = "full"
    LABEL = "label"
    PARTIAL = "partial"
    HASH = "hash"


def is_masked(text: str) -> bool:
    """Return True if ``text`` is exactly a label or digest token this library makes."""
    return _MASKED_TOKEN.fullmatch(text) is not None


def masked_end(text: str, position: int, placeholder: str) -> int:
    """Return where a placeholder or token this library made, starting at ``position``, ends.

    Returns -1 when none starts there. A match that lies inside such a token is a
    previous redaction cut short by a delimiter (``[hidden]`` read up to ``]``).
    """
    if placeholder and text.startswith(placeholder, position):
        return position + len(placeholder)
    token = _MASKED_TOKEN.match(text, position)
    return -1 if token is None else token.end()


def render(
    strategy: Strategy,
    secret: str,
    name: str,
    *,
    placeholder: str,
    keep_last: int,
    hash_length: int,
    hash_key: bytes | None = None,
) -> str:
    """Return the masked form of ``secret`` found by detector ``name``."""
    if secret == placeholder or is_masked(secret):
        return secret
    if strategy is Strategy.LABEL:
        return f"<redacted:{name}>"
    if strategy is Strategy.HASH:
        data = secret.encode("utf-8", "surrogatepass")
        if hash_key is None:
            digest = hashlib.sha256(data).hexdigest()
        else:
            digest = hmac.new(hash_key, data, hashlib.sha256).hexdigest()
        return f"<sha256:{digest[:hash_length]}>"
    if strategy is Strategy.PARTIAL:
        if keep_last <= 0 or len(secret) <= keep_last:
            return placeholder
        return _PARTIAL_FILL * (len(secret) - keep_last) + secret[-keep_last:]
    return placeholder
