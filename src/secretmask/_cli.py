"""Command-line interface for secretmask.

Reads text from an argument, a file or standard input, masks it and writes the
result to standard output as UTF-8. Bytes that are not valid UTF-8 pass through
unchanged. Errors go to standard error with exit status 1; usage errors exit 2.
"""

from __future__ import annotations

import argparse
import errno
import os
import sys
from collections.abc import Sequence

from . import __version__
from ._config import MaskConfig
from ._mask import SecretMask
from ._strategy import Strategy

_EXAMPLES = """\
examples:
  secretmask "Authorization: Bearer abc123def456ghi"
  echo "login a@b.io password=hunter2" | secretmask --strategy partial --keep-last 2
  secretmask --file app.log --strategy hash > app.masked.log
  secretmask --json '{"password": "p", "user": "ada"}'
  secretmask --pattern "ticket=TCK-[0-9]{4}" --allow a@b.io "ref TCK-1234 a@b.io"
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretmask",
        description="Redact secrets in strings, logs and JSON before they are stored.",
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("text", nargs="?", help="text to mask; omit to read standard input")
    parser.add_argument("--file", help="read the input from this file ('-' for standard input)")
    parser.add_argument(
        "--strategy",
        choices=[s.value for s in Strategy],
        default=Strategy.FULL.value,
        help="how to render a secret (default: full)",
    )
    parser.add_argument("--placeholder", default="***", help="replacement for the full strategy")
    parser.add_argument(
        "--keep-last", type=int, default=4, help="characters kept by the partial strategy"
    )
    parser.add_argument(
        "--hash-length", type=int, default=8, help="hex characters kept by the hash strategy"
    )
    for flag, meta, text in (
        ("--pattern", "NAME=REGEX", "add a detector (repeatable)"),
        ("--key", "NAME", "add a sensitive key name (repeatable)"),
        ("--allow", "VALUE", "never mask this exact value (repeatable)"),
    ):
        parser.add_argument(flag, action="append", default=[], metavar=meta, help=text)
    parser.add_argument("--json", action="store_true", help="treat the input as a JSON document")
    parser.add_argument("--no-cards", action="store_true", help="do not mask card numbers")
    parser.add_argument("--version", action="version", version=f"secretmask {__version__}")
    return parser


def _parse_pattern(spec: str) -> tuple[str, str]:
    name, sep, regex = spec.partition("=")
    if not sep or not name or not regex:
        shown = spec if len(spec) <= 40 else spec[:37] + "..."
        raise ValueError(f"--pattern expects NAME=REGEX, got {shown!r}")
    return name, regex


def _decode(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape")


def _read_input(args: argparse.Namespace) -> tuple[str, bool]:
    """Return the input text and whether a newline must be added on output."""
    if args.text is not None:
        if args.file is not None:
            raise ValueError("give the text or --file, not both")
        return str(args.text), True
    if args.file is not None and args.file != "-":
        with open(args.file, "rb") as handle:
            return _decode(handle.read()), False
    if sys.stdin is None:
        raise ValueError("no standard input to read; pass the text or --file")
    raw = getattr(sys.stdin, "buffer", None)
    return (_decode(raw.read()) if raw is not None else sys.stdin.read()), False


def _silence_stdout() -> None:
    # Python flushes stdout again at exit; point it at the null device so that the
    # flush cannot fail a second time on the closed pipe.
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def _write(text: str) -> None:
    raw = getattr(sys.stdout, "buffer", None)
    if raw is None:  # a replaced text stream, as in an embedding application
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    try:
        sys.stdout.flush()
        raw.write(text.encode("utf-8", "surrogateescape"))
        raw.flush()
    except OSError as error:
        # Windows reports a pipe closed by the reader as EINVAL, not as EPIPE.
        if error.errno in (errno.EPIPE, errno.EINVAL):
            raise BrokenPipeError(error.errno, "the reader closed the output") from None
        raise


def _run(args: argparse.Namespace) -> None:
    config = MaskConfig(
        placeholder=args.placeholder,
        extra_patterns=tuple(_parse_pattern(spec) for spec in args.pattern),
        extra_keys=tuple(args.key),
        allowlist=tuple(args.allow),
        mask_credit_cards=not args.no_cards,
        strategy=args.strategy,
        keep_last=args.keep_last,
        hash_length=args.hash_length,
    )
    masker = SecretMask(config)
    text, add_newline = _read_input(args)
    if args.json:
        _write(masker.mask_json(text) + "\n")
    else:
        _write(masker.mask_text(text) + ("\n" if add_newline else ""))


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``secretmask`` console script; returns the exit status."""
    args = _build_parser().parse_args(argv)
    try:
        _run(args)
    except BrokenPipeError:
        # The reader went away (``secretmask ... | head``): not an error of ours.
        _silence_stdout()
        return 0
    except KeyboardInterrupt:
        return 130
    except (ValueError, TypeError, OSError) as error:
        print(f"secretmask: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
