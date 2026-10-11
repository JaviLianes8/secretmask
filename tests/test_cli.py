"""In-process tests of the CLI entry point."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from secretmask._cli import main


def test_masks_a_positional_argument(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["Authorization: Bearer abc123def456ghi"])
    out = capsys.readouterr().out
    assert code == 0
    assert "abc123def456ghi" not in out
    assert "Bearer" in out


def test_reads_from_stdin(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("mail a@b.io"))
    code = main([])
    out = capsys.readouterr().out
    assert code == 0
    assert "a@b.io" not in out


def test_reads_from_a_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "log.txt"
    path.write_text("token=supersecretvalue1", encoding="utf-8")
    code = main(["--file", str(path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "supersecretvalue1" not in out


def test_partial_strategy_option(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--strategy", "partial", "--keep-last", "2", "Bearer abcdefghij"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.strip() == "Bearer ********ij"


def test_json_option_masks_by_structure(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", '{"password": "p", "user": "ada"}'])
    out = capsys.readouterr().out
    assert code == 0
    assert '"user": "ada"' in out
    assert '"p"' not in out


def test_custom_pattern_and_allowlist(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--pattern", r"ticket=TCK-\d{4}", "--allow", "a@b.io", "ref TCK-1234 a@b.io"])
    out = capsys.readouterr().out
    assert code == 0
    assert "TCK-1234" not in out
    assert "a@b.io" in out


def test_bad_pattern_errors_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--pattern", "noequalsign", "text"])
    captured = capsys.readouterr()
    assert code == 1
    assert "secretmask:" in captured.err
    assert captured.out == ""


def test_invalid_json_errors_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", "{not json"])
    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("secretmask:")


def test_missing_file_errors_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--file", "does-not-exist-xyz.txt"])
    captured = capsys.readouterr()
    assert code == 1
    assert "secretmask:" in captured.err
