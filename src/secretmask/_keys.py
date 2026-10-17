"""Sensitive key names: split a key into words and look for a secret name among them."""

from __future__ import annotations

import re

# Words are runs of lower-case letters (optionally after one capital), runs of
# capitals not followed by a lower-case letter, or runs of digits, so "accessToken",
# "ACCESS_TOKEN", "X-Api-Key" and "HTTPAuth2" split the way a reader would split them.
_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_CACHE_LIMIT = 4096
_CACHEABLE = 256


def normalize_key(key: str) -> str:
    """Return ``key`` lower-cased with every separator removed: "X-Api-Key" -> "xapikey"."""
    return "".join(word.lower() for word in _WORD.findall(key))


class KeyMatcher:
    """Decide whether a mapping key names a secret.

    A key is sensitive when one of the names ends a word of it, optionally in the
    plural: "db_password", "accessToken", "accesstoken", "oauth" and "API_KEYS"
    match, "author", "tokenizer" and "passwordless" do not.
    """

    def __init__(self, names: frozenset[str]) -> None:
        self._names = tuple(sorted(name for name in names if name))
        self._cache: dict[str, bool] = {}

    def __call__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = self._match(key)
        if len(key) <= _CACHEABLE:
            if len(self._cache) >= _CACHE_LIMIT:
                self._cache.clear()
            self._cache[key] = result
        return result

    def _match(self, key: str) -> bool:
        words = [word.lower() for word in _WORD.findall(key)]
        joined = "".join(words)
        bounds = {0}
        offset = 0
        for word in words:
            offset += len(word)
            bounds.add(offset)
        for name in self._names:
            start = joined.find(name)
            while start != -1:
                end = start + len(name)
                if end in bounds or (joined[end : end + 1] == "s" and end + 1 in bounds):
                    return True
                start = joined.find(name, start + 1)
        return False
