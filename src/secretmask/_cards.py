"""Payment card numbers: digit groups whose 13 to 19 digits pass the Luhn checksum."""

from __future__ import annotations

import re
from collections.abc import Iterator

# A run of ASCII digit groups joined by single spaces or hyphens. Every group but the
# last has at least three digits, as on card layouts (4-4-4-4, 4-6-5, 4-4-4-4-3, and
# 4-4-4-2 for a 14-digit number), so lists of small numbers never add up to a card.
# Only ASCII digits count, so other scripts' numerals are never read as one. The run
# is maximal and the scan linear.
_RUN = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ -][0-9]{3,})*(?:[ -][0-9]{1,2}(?![0-9]))?")
_DOUBLE = str.maketrans("0123456789", "0246813579")
_GROUP = re.compile(r"[0-9]+")
_MIN_DIGITS = 13
_MAX_DIGITS = 19


def luhn_ok(digits: str) -> bool:
    """Return True if a run of ASCII digits passes the Luhn checksum."""
    # From the right, every second digit is doubled (its digit sum taken).
    kept = sum(map(int, digits[-1::-2]))
    doubled = sum(map(int, digits[-2::-2].translate(_DOUBLE)))
    return (kept + doubled) % 10 == 0


def find_cards(text: str) -> Iterator[tuple[int, int]]:
    """Yield the ``(start, end)`` span of every card number in ``text``.

    A card is whole digit groups (never part of a group) holding 13 to 19 digits
    that pass Luhn, laid out as cards are, taking the longest reading from each group
    and joining readings that overlap. "4111 1111 1111 1111 12/26" yields the card
    and keeps the date, and "qty 197 4689 ..." keeps the quantity.
    """
    for run in _RUN.finditer(text):
        digits = run.group(0)
        groups = [(m.start(), m.end()) for m in _GROUP.finditer(digits)]
        base = run.start()
        # Every group may start a card; overlapping readings ("1234 4421 8096 7929
        # 0814" holds two) are joined, so an ambiguous run is hidden rather than half shown.
        span: tuple[int, int] | None = None
        for index in range(len(groups)):
            found = _longest_card(digits, groups, index)
            if found is None:
                continue
            if span is not None and index <= span[1]:
                span = (span[0], max(span[1], found))
                continue
            if span is not None:
                yield base + groups[span[0]][0], base + groups[span[1]][1]
            span = (index, found)
        if span is not None:
            yield base + groups[span[0]][0], base + groups[span[1]][1]


def _longest_card(run: str, groups: list[tuple[int, int]], first: int) -> int | None:
    # Grouped numbers follow card layouts: four digits first, then groups of four or
    # six (4-4-4-4, 4-6-5, 4-6-4), and a last group of at most six; an unbroken run
    # is read as one group. A number written before the card is then never taken in.
    digits = ""
    best = None
    for last in range(first, len(groups)):
        start, end = groups[last]
        if last > first:
            middle = groups[last - 1][1] - groups[last - 1][0]
            head = groups[first][1] - groups[first][0]
            if head != 4 or end - start > 6 or (last - 1 > first and middle not in (4, 6)):
                break
        digits += run[start:end]
        if len(digits) > _MAX_DIGITS:
            break
        if len(digits) >= _MIN_DIGITS and luhn_ok(digits):
            best = last
    return best
