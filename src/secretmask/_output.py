"""Command-line output: error messages that cannot leak, and bytes that survive."""

from __future__ import annotations

import argparse
import codecs
import re
import sys
from typing import NoReturn

from ._mask import mask_text

OUTPUT_ERRORS = "secretmask.output"
JSON_ERRORS = "secretmask.json"
_LONG_QUOTED = re.compile(r"'([^'\n]{25,})'")
_PREFIX = re.compile(r"-[A-Za-z0-9-]*")
_ESCAPE = b"\\u%04x"


def safe(message: str) -> str:
    """Mask a message and shorten long quoted values before it reaches standard error."""
    message = _LONG_QUOTED.sub(lambda m: f"a value of {len(m.group(1))} characters", message)
    return mask_text(message)


class Parser(argparse.ArgumentParser):
    """An argument parser whose errors never repeat what was typed."""

    # A secret typed in the wrong place ends up here: argparse would quote it.
    # The message is rebuilt from the parser's own option names, never from argparse's
    # text, which may quote what was typed in any style.
    def error(self, message: str) -> NoReturn:
        if message.startswith("unrecognized arguments:"):
            count = len(message.split(":", 1)[1].split())
            message = f"{count} unrecognized argument(s); put text after -- or use --file"
        elif message.startswith("ambiguous option:"):
            typed = _PREFIX.match(message[len("ambiguous option:") :].lstrip())
            prefix = typed.group(0) if typed else ""
            names = sorted(n for n in self._option_string_actions if n.startswith(prefix))
            message = "ambiguous option; it could match " + ", ".join(names)
        elif message.startswith("argument ") and ": " in message:
            head, _, rest = message.partition(": ")
            if "ignored explicit argument" in rest:
                rest = "takes no value"
            elif not rest.startswith("expected"):
                rest = "invalid value"
            message = f"{head}: {rest}"
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {safe(message)}\n")


def _output_errors(error: UnicodeError) -> tuple[bytes, int]:
    # Undecodable input bytes (U+DC80 to U+DCFF) go back out as they came; any other
    # lone surrogate is written as an escape.
    if not isinstance(error, UnicodeEncodeError):
        raise error
    out = bytearray()
    for char in error.object[error.start : error.end]:
        code = ord(char)
        out += bytes([code - 0xDC00]) if 0xDC80 <= code <= 0xDCFF else _ESCAPE % code
    return bytes(out), error.end


def _json_errors(error: UnicodeError) -> tuple[bytes, int]:
    # JSON output writes every lone surrogate as an escape, so it stays valid UTF-8 and
    # parses back to the same string.
    if not isinstance(error, UnicodeEncodeError):
        raise error
    text = error.object[error.start : error.end]
    return b"".join(_ESCAPE % ord(char) for char in text), error.end


codecs.register_error(OUTPUT_ERRORS, _output_errors)
codecs.register_error(JSON_ERRORS, _json_errors)
