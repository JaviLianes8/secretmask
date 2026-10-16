"""Record what detect-secrets finds in the synthetic corpus, as an independent oracle.

    python -m venv oracle && oracle/Scripts/python -m pip install detect-secrets==1.5.0
    oracle/Scripts/python scripts/capture_oracles.py

detect-secrets (Yelp, Apache-2.0) scans every line that ``tests/_corpus.py`` generates
for seeds 0 to 19 with all of its vendor and keyword plugins. The fixture keeps, for
each finding, the seed, the line number, the plugin, the span of the secret in the
line and the SHA-256 of the secret, never the secret itself: the tests regenerate the
line from the seed and check that secretmask hides exactly that text.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class  # noqa: E402
from detect_secrets.core.scan import scan_line  # noqa: E402
from detect_secrets.settings import transient_settings  # noqa: E402

from tests._corpus import keyword_lines, token_lines  # noqa: E402

# Entropy and IP plugins guess rather than recognise a format, so they are left out.
SKIPPED = {"Base64HighEntropyString", "HexHighEntropyString", "IPPublicDetector"}
SEEDS = range(20)


def findings() -> list[list[object]]:
    plugins = [
        {"name": cls.__name__}
        for cls in get_mapping_from_secret_type_to_class().values()
        if cls.__name__ not in SKIPPED
    ]
    out: list[list[object]] = []
    with transient_settings({"plugins_used": plugins}):
        for seed in SEEDS:
            for kind, lines in (("token", token_lines(seed)), ("keyword", keyword_lines(seed))):
                for number, line in enumerate(lines):
                    for secret in scan_line(line):
                        value = secret.secret_value or ""
                        start = line.find(value)
                        if not value or start < 0:
                            continue
                        digest = hashlib.sha256(value.encode()).hexdigest()
                        out.append(
                            [seed, kind, number, secret.type, start, start + len(value), digest]
                        )
    return out


def main() -> int:
    found = findings()
    document = {
        "tool": "detect-secrets",
        "version": importlib.metadata.version("detect-secrets"),
        "python": sys.version.split()[0],
        "seeds": [SEEDS.start, SEEDS.stop],
        "columns": ["seed", "kind", "line", "plugin", "start", "end", "sha256"],
        "findings": found,
    }
    target = ROOT / "tests" / "fixtures" / "detect_secrets.json"
    target.parent.mkdir(exist_ok=True)
    head = json.dumps({k: v for k, v in document.items() if k != "findings"})[:-1]
    rows = ",\n".join(json.dumps(row) for row in found)
    target.write_text(f'{head}, "findings": [\n{rows}\n]}}\n', "utf-8", newline="\n")
    print(f"{len(found)} findings written to {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
