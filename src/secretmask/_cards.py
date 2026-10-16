"""Payment card numbers: digit groups whose 13 to 19 digits pass the Luhn checksum."""

from __future__ import annotations

import re
from collections.abc import Iterator

# A run of ASCII digit groups joined by single spaces or hyphens, each group at least
# three digits long as on every card layout (4-4-4-4, 4-6-5, 4-4-4-4-3), so lists of
# small numbers never add up to a card. Only ASCII digits count, so other scripts'
# numerals are never read as one. The run is maximal and the scan linear.
_RUN = re.compile(r"(?<![0-9])[0-9]{3,}(?:[ -][0-9]{3,})*")
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
    that pass Luhn. Within a run the longest card starting at the leftmost group is
    taken, so "4111 1111 1111 1111 12/26" yields the card and keeps the date.
    """
    for run in _RUN.finditer(text):
        digits = run.group(0)
        groups = [(m.start(), m.end()) for m in _GROUP.finditer(digits)]
        base = run.start()
        index = 0
        while index < len(groups):
            found = _longest_card(digits, groups, index)
            if found is None:
                index += 1
                continue
            yield base + groups[index][0], base + groups[found][1]
            index = found + 1


def _longest_card(run: str, groups: list[tuple[int, int]], first: int) -> int | None:
    digits = ""
    best = None
    for last in range(first, len(groups)):
        start, end = groups[last]
        digits += run[start:end]
        if len(digits) > _MAX_DIGITS:
            break
        if len(digits) >= _MIN_DIGITS and luhn_ok(digits):
            best = last
    return best
