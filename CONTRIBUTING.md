# Contributing

Thanks for taking the time. This project keeps a small, predictable shape.

## Setup

```
pip install -r requirements-dev.txt
```

## Before you open a pull request

- Keep public API in `src/secretmask/__init__.py`; internals live in `_`-prefixed modules.
- Add a test for the behaviour you change. Tests inject time, disk and network; they
  never touch the real thing.
- Run `scripts/check.ps1` (format, lint, types, tests) and make sure it passes. With
  `SECRETMASK_E2E=1` it also builds the wheel, installs it and upgrades from PyPI.
- The ground-truth tests read vendor documentation, RFCs and other scanners' rule
  sets that are never committed: run `python scripts/fetch_sources.py` once to fetch
  them (they skip otherwise). A new detector needs its format source in GUIDE.md.
- One logical change per commit, imperative subject line.

Open an issue first if the change is large or shifts the public API.
