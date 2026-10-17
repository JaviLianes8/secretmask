"""The command-line interface, in process and as a real subprocess."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secretmask import __version__
from secretmask._cli import main

SRC = str(Path(__file__).resolve().parent.parent / "src")


def _run(*args: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "PYTHONPATH": SRC}
    return subprocess.run(
        [sys.executable, "-m", "secretmask", *args],
        input=stdin,
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )


def test_masks_a_positional_argument(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["Authorization: Bearer abc123def456ghi"]) == 0
    assert capsys.readouterr().out == "Authorization: Bearer ***\n"


def test_reads_a_text_stdin(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("mail a@b.io\n"))
    assert main([]) == 0
    assert capsys.readouterr().out == "mail ***\n"


def test_options_reach_the_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--strategy", "partial", "--keep-last", "2", "Bearer abcdefghij"]) == 0
    assert capsys.readouterr().out == "Bearer ********ij\n"
    assert main(["--strategy", "hash", "--hash-length", "4", "a@b.io"]) == 0
    assert capsys.readouterr().out.startswith("<sha256:") is True
    assert main(["--placeholder", "#", "--key", "iban", "--json", '{"iban": 1}']) == 0
    assert capsys.readouterr().out == '{"iban": "#"}\n'
    assert main(["--no-cards", "4242 4242 4242 4242"]) == 0
    assert capsys.readouterr().out == "4242 4242 4242 4242\n"
    args = ["--pattern", "ticket=TCK-[0-9]{4}", "--allow", "a@b.io", "ref TCK-1234 a@b.io"]
    assert main(args) == 0
    assert capsys.readouterr().out == "ref *** a@b.io\n"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--pattern", "t=(", "x"], "pattern 't' is not a valid regex"),
        (["--keep-last", "-1", "x"], "keep_last must be at least 0"),
        (["--json", "{not json"], "Expecting property name"),
        (["--file", "does-not-exist-xyz.txt"], "No such file"),
    ],
)
def test_errors_go_to_stderr_with_status_1(
    args: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("secretmask: ") and message in captured.err


def test_a_file_is_masked_byte_for_byte(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_bytes(b"caf\xc3\xa9 token=s3cr3t\r\nraw \xff\xfe a@b.io\n")
    result = _run("--file", str(path))
    assert result.returncode == 0, result.stderr
    assert result.stdout == b"caf\xc3\xa9 token=***\r\nraw \xff\xfe ***\n"


def test_stdin_is_masked_without_adding_a_newline() -> None:
    result = _run(stdin=b"line one a@b.io\nline two")
    assert result.stdout == b"line one ***\nline two"
    assert _run("--file", "-", stdin=b"pwd=x\n").stdout == b"pwd=***\n"


def test_json_mode_by_subprocess_and_version() -> None:
    result = _run("--json", stdin='{"password": "p", "user": "José"}\n'.encode())
    assert result.stdout.decode("utf-8") == '{"password": "***", "user": "José"}\n'
    assert _run("--version").stdout.decode().strip() == f"secretmask {__version__}"


def test_usage_errors_exit_2() -> None:
    assert _run("--strategy", "nope", "x").returncode == 2
    assert _run("--keep-last", "many", "x").returncode == 2
    bad = [["--pattern", p, "x"] for p in ("noequalsign", "n=", "=x")]
    bad += [["--pattern", "a=b", "--pattern", "bad", "x"], ["--file", "f.txt", "text"]]
    for args in bad:
        result = _run(*args)
        assert result.returncode == 2 and b"usage: secretmask" in result.stderr, args


def test_a_pattern_regex_may_contain_and_end_with_equals(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--pattern", "kv=k=[0-9]+", "--pattern", "b64=QQ==", "k=12 QQ=="]) == 0
    assert capsys.readouterr().out == "*** ***\n"


def test_a_closed_reader_is_not_an_error() -> None:
    code = (
        "import sys, subprocess\n"
        "p = subprocess.Popen([sys.executable, '-m', 'secretmask'], stdin=subprocess.PIPE,"
        " stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
        "p.stdout.close()\n"
        "_, err = p.communicate(b'a@b.io ' * 400000)\n"
        "print(p.returncode, len(err))\n"
    )
    env = {**os.environ, "PYTHONPATH": SRC}
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120, env=env
    )
    assert result.stdout.split()[:2] == ["0", "0"], result.stdout


def test_error_messages_never_repeat_a_secret_or_a_long_value() -> None:
    token = "ghp_" + "Q" * 36
    cases = [
        ["--token=" + token],
        ["-" + token],
        ["--strategy", token, "x"],
        ["--keep-last", token, "x"],
        ["--file", "missing-" + "x" * 100],
        ["--pattern", "n=(" + token, "x"],
    ]
    for args in cases:
        result = _run(*args)
        assert result.returncode in (1, 2), args
        assert token.encode() not in result.stderr, args
        assert b"x" * 50 not in result.stderr, args


def test_json_with_an_escaped_lone_surrogate_is_written_back_escaped() -> None:
    result = _run("--json", stdin=b'{"a": "\\ud800", "token": "t"}')
    assert result.returncode == 0, result.stderr
    assert result.stdout == b'{"a": "\\ud800", "token": "***"}\n'


def test_no_typed_value_reaches_standard_error() -> None:
    secret = "hunter2pwLongEnoughToSee"
    cases = [
        ["-X" + secret],
        ["--strategy", secret, "x"],
        ["--keep-last", secret, "x"],
        ["--ke=" + secret],
        ["--json=" + secret],
        ["--no-cards=" + secret],
    ]
    for args in cases:
        result = _run(*args)
        assert result.returncode == 2, args
        assert secret.encode() not in result.stderr, args
    many = _run("a", "b", "c")
    assert b"2 unrecognized argument(s)" in many.stderr


def test_long_quoted_values_in_errors_are_described_by_length() -> None:
    short = _run("--file", "m" * 24)
    long = _run("--file", "m" * 25)
    assert b"m" * 24 in short.stderr
    assert b"m" * 25 not in long.stderr and b"a value of 25 characters" in long.stderr


def test_lone_surrogates_in_text_and_json_output(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    assert main(["x\udc41y"]) == 0
    assert capsysbinary.readouterr().out == b"x\\udc41y\n"
    assert main(["x\ud800y"]) == 0
    assert capsysbinary.readouterr().out == b"x\\ud800y\n"
    raw = _run(stdin=b"a\x80 b")
    assert raw.stdout == b"a\x80 b"
    escaped = _run("--json", stdin=b'{"a": "\\udc80"}')
    assert escaped.stdout == b'{"a": "\\udc80"}\n'
