"""Redaction strategies: how a detected secret is turned into its masked form."""

from __future__ import annotations

import hashlib
import re
from enum import Enum

_PARTIAL_FILL = "*"

# A token this module itself produces. Re-rendering one returns it unchanged, so
# masking an already-masked string is a no-op (idempotence), even for HASH, whose
# digest would otherwise be hashed again into a different value.
_MASKED_TOKEN = re.compile(r"\A<redacted:[^>]*>\Z|\A<sha256:[0-9a-f]+>\Z")


class Strategy(str, Enum):
    """How a detected secret is rendered once it has been found.

    - ``FULL`` replaces the secret with the configured placeholder.
    - ``LABEL`` names the detector, for example ``<redacted:jwt>``.
    - ``PARTIAL`` keeps the last ``keep_last`` characters and masks the rest,
      for example ``************ghi``; a secret no longer than ``keep_last`` is
      masked in full so nothing is ever revealed outright.
    - ``HASH`` replaces the secret with a short deterministic SHA-256 digest,
      for example ``<sha256:ab12cd34>``, so the same secret is correlatable
      across lines without being readable.

    It is a :class:`str` enum, so ``"partial"`` and ``Strategy.PARTIAL`` are
    interchangeable and it serialises as plain text.
    """

    FULL = "full"
    LABEL = "label"
    PARTIAL = "partial"
    HASH = "hash"


def render(
    strategy: Strategy,
    secret: str,
    name: str,
    *,
    placeholder: str,
    keep_last: int,
    hash_length: int,
) -> str:
    """Return the masked form of ``secret`` found by detector ``name``."""
    if secret == placeholder or _MASKED_TOKEN.match(secret):
        return secret
    if strategy is Strategy.LABEL:
        return f"<redacted:{name}>"
    if strategy is Strategy.HASH:
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:hash_length]
        return f"<sha256:{digest}>"
    if strategy is Strategy.PARTIAL:
        if keep_last <= 0 or len(secret) <= keep_last:
            return placeholder
        return _PARTIAL_FILL * (len(secret) - keep_last) + secret[-keep_last:]
    return placeholder
