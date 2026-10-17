"""Find every secret in one string and replace each once, earliest detector first."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from ._cards import find_cards
from ._patterns import BUILTIN_PATTERNS, EMAIL
from ._strategy import masked_end

CARD_NAME = "credit_card"

# (start, end, detector name, keep): ``keep`` marks an allowlisted value or an earlier
# redaction, which stays as it is.
_Span = tuple[int, int, str, bool]


def _clashes(merged: list[_Span], taken: list[_Span], index: int, span: _Span) -> bool:
    # True if ``span`` overlaps a span of a detector it yields to (see _EMAIL_YIELDS_TO).
    if merged and merged[-1][1] > span[0] and merged[-1][2] in _EMAIL_YIELDS_TO:
        return True
    while index < len(taken) and taken[index][0] < span[1]:
        if taken[index][2] in _EMAIL_YIELDS_TO:
            return True
        index += 1
    return False


def _merge(taken: list[_Span], found: Iterable[_Span], *, yields: bool = False) -> list[_Span]:
    """Add the spans of one later detector to ``taken``.

    A span that overlaps earlier ones is joined with them into one span, named after
    the earlier detector, so a secret is replaced once as a whole and masking the
    result again finds nothing new. Both inputs are sorted and free of overlaps, and
    one linear pass keeps the result so.
    """
    merged: list[_Span] = []
    index = 0
    for span in found:
        while index < len(taken) and taken[index][1] <= span[0]:
            merged.append(taken[index])
            index += 1
        if yields and _clashes(merged, taken, index, span):
            continue
        group: list[_Span] = []
        if merged and merged[-1][1] > span[0]:
            group.append(merged.pop())
        end = span[1]
        while index < len(taken) and taken[index][0] < end:
            group.append(taken[index])
            end = max(end, taken[index][1])
            index += 1
        if group:
            start = min(group[0][0], span[0])
            keep = span[3] and all(part[3] for part in group)
            span = (start, max(end, group[-1][1]), group[0][2], keep)
        merged.append(span)
    merged.extend(taken[index:])
    return merged


def _is_masked(text: str, start: int, end: int, placeholder: str) -> bool:
    """Return True if ``text[start:end]`` lies within earlier redactions, back to back."""
    position = start
    while position < end:
        position = masked_end(text, position, placeholder)
        if position < 0:
            return False
    return True


def _join_adjacent(spans: list[_Span]) -> list[_Span]:
    # Two redactions that touch become one, so the output never shows two masks back
    # to back that a later pass could read as one longer secret.
    joined: list[_Span] = []
    for span in spans:
        if joined and joined[-1][1] == span[0]:
            last = joined.pop()
            span = (last[0], span[1], last[2], last[3] and span[3])
        joined.append(span)
    return joined


_EMAIL_REGEX = dict(BUILTIN_PATTERNS)[EMAIL]
# The part of "://user:p+w@db.example.com" after the password reads as an address;
# where the password is already hidden, the address yields, so the host is kept.
_EMAIL_YIELDS_TO = frozenset({"url_credentials"})


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
        yield (
            start,
            end,
            name,
            text[start:end] in allow or _is_masked(text, start, end, placeholder),
        )


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
        found = _pattern_spans(text, name, regex, allow, placeholder)
        taken = _merge(taken, found, yields=regex.pattern == _EMAIL_REGEX)
    if cards:
        cards_found = (
            (start, end, CARD_NAME, text[start:end] in allow) for start, end in find_cards(text)
        )
        taken = _merge(taken, cards_found)
    if not taken:
        return text
    taken = _join_adjacent(taken)
    pieces: list[str] = []
    cursor = 0
    for start, end, name, keep in taken:
        pieces.append(text[cursor:start])
        secret = text[start:end]
        pieces.append(secret if keep else render(secret, name))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)
