"""End to end: build the wheel, install it in a fresh venv, use it as an outsider would.

Opt in with ``SECRETMASK_E2E=1``: building needs the build backend and the upgrade
check installs the published 0.2.0 from PyPI, so both reach the network.
"""

from __future__ import annotations

import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(
    os.environ.get("SECRETMASK_E2E") != "1", reason="set SECRETMASK_E2E=1 to build and install"
)

# Only what 0.2.0 offered, so the same script runs before and after the upgrade.
OLD_CONSUMER = """
import secretmask
from secretmask import MaskConfig, SecretMask, Strategy, mask, mask_json, mask_text

assert mask_text("Authorization: Bearer abc123def456ghi") == "Authorization: Bearer ***"
assert mask({"password": "hunter2", "n": [1, "a@b.io"]}) == {"password": "***", "n": [1, "***"]}
assert mask_json('{"token": "t", "user": "ada"}') == '{"token": "***", "user": "ada"}'
config = MaskConfig(placeholder="#", extra_keys=("iban",), extra_patterns=(("t", "T-[0-9]+"),),
                    allowlist=("keep@b.io",), strategy=Strategy.LABEL)
masker = SecretMask(config)
assert masker.mask_text("T-12 keep@b.io x@b.io") == "<redacted:t> keep@b.io <redacted:email>"
assert masker.mask({"iban": "ES"}) == {"iban": "<redacted:iban>"}
assert mask_text("a@b.io", config=MaskConfig(label=True)) == "<redacted:email>"
assert mask_text("Bearer abcdefghij", config=MaskConfig(strategy="partial", keep_last=3)) \\
    == "Bearer *******hij"
print("old api ok", secretmask.__version__)
"""

CONSUMER = """
import secretmask
from secretmask import MaskConfig, SecretMask, mask, mask_text

assert "site-packages" in secretmask.__file__, secretmask.__file__
assert mask_text("AWS_SECRET_ACCESS_KEY=abc client_secret: x") == (
    "AWS_SECRET_ACCESS_KEY=*** client_secret: ***"
)
keyed = SecretMask(MaskConfig(strategy="hash", hash_key=b"pepper"))
assert keyed.mask_text("a@b.io").startswith("<sha256:")
loop = []
loop.append(loop)
try:
    mask(loop)
except ValueError:
    pass
else:
    raise AssertionError("a cycle must raise")
print("consumer ok", secretmask.__version__)
"""


def _sh(*cmd: str, cwd: str | None = None, data: bytes | None = None) -> bytes:
    result = subprocess.run(cmd, capture_output=True, timeout=600, check=False, cwd=cwd, input=data)
    assert result.returncode == 0, f"{cmd}\n{result.stdout!r}\n{result.stderr!r}"
    return result.stdout


def _venv(where: Path) -> Path:
    venv.EnvBuilder(with_pip=True).create(where)
    return where / ("Scripts" if os.name == "nt" else "bin")


def _python(bindir: Path) -> str:
    return str(bindir / ("python.exe" if os.name == "nt" else "python"))


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    dist = tmp_path_factory.mktemp("dist")
    _sh(sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(dist), str(ROOT))
    wheels = list(dist.glob("secretmask-1.0.0-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


@pytest.fixture(scope="module")
def installed(wheel: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    bindir = _venv(tmp_path_factory.mktemp("e2e") / "venv")
    _sh(_python(bindir), "-m", "pip", "install", "-q", "--no-index", str(wheel))
    return bindir


def test_upgrading_from_the_published_0_2_0_keeps_old_code_working(
    wheel: Path, tmp_path: Path
) -> None:
    bindir = _venv(tmp_path / "venv")
    script = tmp_path / "old.py"
    script.write_text(OLD_CONSUMER, encoding="utf-8")
    _sh(_python(bindir), "-m", "pip", "install", "-q", "--no-cache-dir", "secretmask==0.2.0")
    assert _sh(_python(bindir), str(script), cwd=str(tmp_path)).split() == [
        b"old",
        b"api",
        b"ok",
        b"0.2.0",
    ]
    _sh(_python(bindir), "-m", "pip", "install", "-q", "--no-index", "--upgrade", str(wheel))
    assert _sh(_python(bindir), str(script), cwd=str(tmp_path)).split()[-1] == b"1.0.0"


def test_the_installed_wheel_works_for_a_consumer(installed: Path, tmp_path: Path) -> None:
    script = tmp_path / "consumer.py"
    script.write_text(CONSUMER, encoding="utf-8")
    assert _sh(_python(installed), str(script), cwd=str(tmp_path)).split() == [
        b"consumer",
        b"ok",
        b"1.0.0",
    ]
    code = "import importlib.resources as r; print(r.files('secretmask').joinpath('py.typed'))"
    assert Path(_sh(_python(installed), "-c", code).strip().decode()).is_file()


def test_the_installed_console_script(installed: Path, tmp_path: Path) -> None:
    exe = str(installed / ("secretmask.exe" if os.name == "nt" else "secretmask"))
    log = tmp_path / "app.log"
    log.write_bytes(b"GET /?access_token=abc123&page=2\r\nuser a@b.io \xff\n")
    assert _sh(exe, "--file", str(log)) == b"GET /?access_token=***&page=2\r\nuser *** \xff\n"
    assert _sh(exe, "--json", data=b'{"pwd": "x"}') == b'{"pwd": "***"}\n'
    assert _sh(exe, "--version").strip() == b"secretmask 1.0.0"
    assert _sh(_python(installed), "-m", "secretmask", "Bearer abcdefgh1") == b"Bearer ***\n"
    bad = subprocess.run([exe, "--pattern", "x=(", "t"], capture_output=True, timeout=60)
    assert bad.returncode == 1 and bad.stderr.startswith(b"secretmask: ")
