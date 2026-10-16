# Local quality gate. Run before every commit. No CI runs in the cloud.
# Set SECRETMASK_E2E=1 to also build the wheel, install it and upgrade from PyPI 0.2.0.
$ErrorActionPreference = "Stop"

ruff format --check .
if ($LASTEXITCODE) { exit $LASTEXITCODE }
ruff check .
if ($LASTEXITCODE) { exit $LASTEXITCODE }
mypy --strict src tests scripts
if ($LASTEXITCODE) { exit $LASTEXITCODE }
pytest
if ($LASTEXITCODE) { exit $LASTEXITCODE }
