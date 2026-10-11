"""Real end-to-end test: install the package and drive the installed CLI.

No mocks. A throwaway virtual environment is created, ``secretmask`` is installed
into it as an editable install, and the real console script is run as a
subprocess on real inputs. The tests assert the real stdout, the real exit code,
and that no secret ever leaks into the output.
"""

from __future__ import annotations

import os
import subprocess
import venv
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def console_script(tmp_path_factory: pytest.TempPathFactory) -> Path:
    env_dir = tmp_path_factory.mktemp("sm_venv")
    venv.create(env_dir, with_pip=True, clear=True)
    bin_dir = env_dir / ("Scripts" if os.name == "nt" else "bin")
    python = bin_dir / ("python.exe" if os.name == "nt" else "python")
    subprocess.run(
        [str(python), "-m", "pip", "install", "-e", str(_ROOT), "-q"],
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    )
    script = bin_dir / ("secretmask.exe" if os.name == "nt" else "secretmask")
    assert script.is_file(), "the console script was not installed"
    return script


def _run(
    script: Path, args: list[str], stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [str(script), *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env=env,
    )


def test_installed_cli_reports_its_version(console_script: Path) -> None:
    result = _run(console_script, ["--version"])
    assert result.returncode == 0
    assert result.stdout.strip() == f"secretmask {_read_version()}"


def test_installed_cli_masks_a_positional_argument(console_script: Path) -> None:
    secret = "Authorization: Bearer abc123def456ghi"
    result = _run(console_script, [secret])
    assert result.returncode == 0
    assert "abc123def456ghi" not in result.stdout
    assert "Bearer" in result.stdout


def test_installed_cli_masks_stdin_and_leaks_nothing(console_script: Path) -> None:
    payload = "login a@b.io pass password=hunter2 key AKIAIOSFODNN7EXAMPLE card 4111 1111 1111 1111"
    result = _run(console_script, ["--strategy", "label"], stdin=payload)
    assert result.returncode == 0
    for secret in ("a@b.io", "hunter2", "AKIAIOSFODNN7EXAMPLE", "4111 1111 1111 1111"):
        assert secret not in result.stdout


def test_installed_cli_masks_json_by_structure(console_script: Path) -> None:
    result = _run(console_script, ["--json", '{"password": "p", "user": "ada", "note": "a@b.io"}'])
    assert result.returncode == 0
    assert '"user": "ada"' in result.stdout
    assert "a@b.io" not in result.stdout


def test_installed_cli_handles_unicode_without_corruption(console_script: Path) -> None:
    result = _run(console_script, ["café 你好 mail a@b.io"])
    assert result.returncode == 0
    assert "café 你好" in result.stdout
    assert "a@b.io" not in result.stdout


def test_installed_cli_reports_errors_to_stderr(console_script: Path) -> None:
    result = _run(console_script, ["--json", "{not json"])
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("secretmask:")


def _read_version() -> str:
    text = (_ROOT / "src" / "secretmask" / "__init__.py").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("__version__"):
            return line.split('"')[1]
    raise AssertionError("version not found")
