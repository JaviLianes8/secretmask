"""Command-line interface for secretmask.

Reads text from an argument, a file or standard input, masks it and writes the
result to standard output. Errors go to standard error with exit code 1.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from ._config import MaskConfig
from ._mask import SecretMask
from ._strategy import Strategy

_EXAMPLES = """\
examples:
  secretmask "Authorization: Bearer abc123def456ghi"
  echo "login a@b.io pass=hunter2" | secretmask --strategy partial --keep-last 2
  secretmask --file app.log --strategy hash
  secretmask --json '{"password": "p", "user": "ada"}'
  secretmask --pattern "ticket=TCK-\\d{4}" --allow a@b.io "ref TCK-1234 a@b.io"
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretmask",
        description="Redact secrets in strings, logs and JSON before they are stored.",
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("text", nargs="?", help="text to mask; omit to read standard input")
    parser.add_argument("--file", help="read the input from this file instead of an argument")
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
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        metavar="NAME=REGEX",
        help="add a detector (repeatable)",
    )
    parser.add_argument(
        "--key",
        action="append",
        default=[],
        metavar="NAME",
        help="add a sensitive key (repeatable)",
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="VALUE",
        help="never mask this value (repeatable)",
    )
    parser.add_argument("--json", action="store_true", help="treat the input as a JSON document")
    parser.add_argument("--no-cards", action="store_true", help="do not mask credit-card numbers")
    parser.add_argument("--version", action="version", version=f"secretmask {__version__}")
    return parser


def _parse_pattern(spec: str) -> tuple[str, str]:
    name, sep, regex = spec.partition("=")
    if not sep or not name or not regex:
        raise ValueError(f"--pattern expects NAME=REGEX, got {spec!r}")
    return name, regex


def _read_input(args: argparse.Namespace) -> str:
    if args.text is not None:
        return str(args.text)
    if args.file is not None:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    return sys.stdin.read()


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``secretmask`` console script."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        patterns = tuple(_parse_pattern(spec) for spec in args.pattern)
        config = MaskConfig(
            placeholder=args.placeholder,
            extra_patterns=patterns,
            extra_keys=tuple(args.key),
            allowlist=tuple(args.allow),
            mask_credit_cards=not args.no_cards,
            strategy=args.strategy,
            keep_last=args.keep_last,
            hash_length=args.hash_length,
        )
        masker = SecretMask(config)
        text = _read_input(args)
        output = masker.mask_json(text) if args.json else masker.mask_text(text)
    except (ValueError, OSError) as error:
        print(f"secretmask: {error}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
