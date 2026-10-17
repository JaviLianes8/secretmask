"""Walk nested data without recursion, so depth is limited only by memory."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from typing import Any


def _is_container(value: object) -> bool:
    return isinstance(value, (Mapping, list, tuple))


class _Frame:
    __slots__ = ("is_map", "key", "out", "pairs", "source")

    def __init__(self, source: Any, key: object) -> None:
        self.source = source
        self.key = key
        self.is_map = isinstance(source, Mapping)
        self.pairs: Iterator[tuple[object, Any]] = (
            iter(source.items()) if self.is_map else iter(enumerate(source))
        )
        self.out: list[tuple[object, Any]] = []

    def build(self) -> Any:
        if self.is_map:
            return dict(self.out)
        items = [item for _, item in self.out]
        return tuple(items) if isinstance(self.source, tuple) else items


def walk(
    value: Any,
    *,
    leaf: Callable[[str], str],
    sensitive: Callable[[object], bool],
    hide: Callable[[str, Any], Any],
) -> Any:
    """Return a masked copy of ``value``.

    Strings go through ``leaf``; in a mapping, the value of a key for which
    ``sensitive`` is true goes through ``hide`` instead and is not walked. Mappings
    become dicts, lists stay lists, tuples become plain tuples, anything else is
    returned as it is. A structure that contains itself raises ``ValueError``.
    """
    if isinstance(value, str):
        return leaf(value)
    if not _is_container(value):
        return value
    active = {id(value)}
    # A container met again (not inside itself) gets the copy already made, so data
    # that shares objects costs its size, not the size of its unfolding.
    # Each entry keeps its source alive, so an id is never reused for another object.
    done: dict[int, tuple[Any, Any]] = {}
    stack = [_Frame(value, None)]
    while True:
        frame = stack[-1]
        for key, item in frame.pairs:
            if frame.is_map and sensitive(key):
                frame.out.append((key, hide(str(key), item)))
            elif isinstance(item, str):
                frame.out.append((key, leaf(item)))
            elif id(item) in done and done[id(item)][0] is item:
                frame.out.append((key, done[id(item)][1]))
            elif _is_container(item):
                if id(item) in active:
                    raise ValueError("cannot mask a structure that contains itself")
                active.add(id(item))
                stack.append(_Frame(item, key))
                break
            else:
                frame.out.append((key, item))
        else:
            stack.pop()
            active.discard(id(frame.source))
            result = frame.build()
            done[id(frame.source)] = (frame.source, result)
            if not stack:
                return result
            stack[-1].out.append((frame.key, result))
