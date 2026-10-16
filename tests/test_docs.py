"""Every example in the docstrings, the README and the guide runs and prints what it says."""

from __future__ import annotations

import doctest
import importlib
import pkgutil
import re
from pathlib import Path

import pytest

import secretmask
from secretmask._cli import main

ROOT = Path(__file__).resolve().parent.parent
MODULES = ["secretmask"] + [
    f"secretmask.{m.name}" for m in pkgutil.iter_modules(secretmask.__path__)
]


@pytest.mark.parametrize("name", MODULES)
def test_module_doctests_pass(name: str) -> None:
    result = doctest.testmod(importlib.import_module(name), optionflags=doctest.ELLIPSIS)
    assert result.failed == 0


@pytest.mark.parametrize("name", secretmask.__all__)
def test_every_public_name_runs_its_own_examples(name: str) -> None:
    tests = doctest.DocTestFinder().find(getattr(secretmask, name), name, module=False)
    assert sum(len(t.examples) for t in tests) >= 1
    runner = doctest.DocTestRunner(optionflags=doctest.ELLIPSIS)
    for test in tests:
        test.globs = {n: getattr(secretmask, n) for n in secretmask.__all__}
        runner.run(test)
    assert runner.summarize(verbose=False).failed == 0


def test_the_masker_methods_carry_examples() -> None:
    for method in ("mask_text", "mask", "mask_json"):
        tests = doctest.DocTestFinder().find(getattr(secretmask.SecretMask, method))
        assert any(t.examples for t in tests), method


def _expected(block: str) -> list[str]:
    """The output a block promises: comments after or beside its print() calls."""
    expected: list[str] = []
    after_print = False
    for line in block.splitlines():
        if line.startswith("print("):
            after_print = True
            inline = re.search(r"\)  # (.*)$", line)
            if inline:
                expected.append(inline.group(1))
                after_print = False
        elif after_print and line.startswith("# "):
            expected.append(line[2:])
            after_print = False
        elif not line.startswith(("    ", ")")):
            after_print = False
    return expected


@pytest.mark.parametrize("name", ["README.md", "GUIDE.md"])
def test_python_examples_print_what_they_say(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    blocks = re.findall(r"```python\n(.*?)```", (ROOT / name).read_text("utf-8"), flags=re.S)
    assert len(blocks) >= 2
    for block in blocks:
        exec(compile(block, name, "exec"), {"__name__": "__docs__"})
        printed = capsys.readouterr().out.splitlines()
        assert printed and printed == _expected(block), block


def test_readme_shell_examples(capsys: pytest.CaptureFixture[str]) -> None:
    text = (ROOT / "README.md").read_text("utf-8")
    assert '$ secretmask "token=abc123"\ntoken=***' in text
    assert main(["token=abc123"]) == 0
    assert capsys.readouterr().out == "token=***\n"
    assert main(["--json", '{"password": "p", "user": "ada"}']) == 0
    assert capsys.readouterr().out == '{"password": "***", "user": "ada"}\n'


def test_links_are_absolute_and_docs_are_clean() -> None:
    readme = (ROOT / "README.md").read_text("utf-8")
    links = re.findall(r"\]\(([^)]+)\)", readme)
    assert links and all(link.startswith("https://") for link in links)
    for name in ["README.md", "GUIDE.md", "CHANGELOG.md", "CONTRIBUTING.md"]:
        text = (ROOT / name).read_text("utf-8")
        assert chr(0x2014) not in text, name


def test_the_guide_lists_every_builtin_detector() -> None:
    from secretmask._patterns import BUILTIN_PATTERNS

    guide = (ROOT / "GUIDE.md").read_text("utf-8")
    for name, _ in BUILTIN_PATTERNS:
        assert f"| `{name}` |" in guide, name
    assert "| `credit_card` |" in guide
