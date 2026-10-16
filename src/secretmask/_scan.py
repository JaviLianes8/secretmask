"""Find every secret in one string and replace each once, earliest detector first."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from ._cards import find_cards
from ._strategy import masked_end

CARD_NAME = "credit_card"

# (start, end, detector name, keep): ``keep`` marks an allowlisted value or an earlier
# redaction, which stays as it is but still blocks the detectors that come after it.
_Span = tuple[int, int, str, bool]


def _merge(taken: list[_Span], found: Iterable[_Span]) -> list[_Span]:
    """Add the spans of one detector to ``taken``, dropping any that overlap it.

    Both inputs are sorted and free of overlaps, so one linear pass keeps the
    result sorted and free of overlaps too.
    """
    merged: list[_Span] = []
    index = 0
    for span in found:
        while index < len(taken) and taken[index][1] <= span[0]:
            merged.append(taken[index])
            index += 1
        if index < len(taken) and taken[index][0] < span[1]:
            continue
        merged.append(span)
    merged.extend(taken[index:])
    return merged


def _pattern_spans(
    text: str, name: str, regex: re.Pattern[str], allow: frozenset[str], placeholder: str
) -> Iterable[_Span]:
    partial = "s" in regex.groupindex
    for match in regex.finditer(text):
        start, end = match.span("s") if partial else match.span()
        if start < 0:
            start, end = match.span()
        if start == end:
            continue
        keep = text[start:end] in allow or masked_end(text, start, placeholder) >= end
        yield start, end, name, keep


def mask_string(
    text: str,
    patterns: Iterable[tuple[str, re.Pattern[str]]],
    *,
    cards: bool,
    allow: frozenset[str],
    placeholder: str,
    render: Callable[[str, str], str],
) -> str:
    """Return ``text`` with every detected secret replaced by ``render(secret, name)``."""
    taken: list[_Span] = []
    for name, regex in patterns:
        taken = _merge(taken, _pattern_spans(text, name, regex, allow, placeholder))
    if cards:
        found = (
            (start, end, CARD_NAME, text[start:end] in allow) for start, end in find_cards(text)
        )
        taken = _merge(taken, found)
    if not taken:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end, name, keep in taken:
        pieces.append(text[cursor:start])
        secret = text[start:end]
        pieces.append(secret if keep else render(secret, name))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)
