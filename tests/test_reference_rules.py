"""Independent oracles: other scanners' rules and findings, checked against masking.

gitleaks and trufflehog rule files are fetched by ``scripts/fetch_sources.py`` (pinned
commits, never committed) and compiled here; detect-secrets findings are recorded in
``tests/fixtures/detect_secrets.json`` by ``scripts/capture_oracles.py`` and, when the
package is installed, also produced live. Whatever those tools call a secret in the
synthetic corpus must be gone after masking.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path

import pytest

from secretmask import mask_text

from ._corpus import keyword_lines, slack_webhook, token_lines, tokens

HERE = Path(__file__).resolve().parent
GITLEAKS_RULES = (
    "aws-access-token",
    "gcp-api-key",
    "generic-api-key",
    "github-",
    "jwt",
    "openai-api-key",
    "private-key",
    "slack-",
    "stripe-access-token",
)


def _rules() -> dict[str, re.Pattern[str]]:
    tomllib = pytest.importorskip("tomllib")  # Python 3.11 and later
    toml = HERE / "sources" / "gitleaks.toml"
    if not toml.is_file():
        pytest.skip("reference rules not fetched; run scripts/fetch_sources.py")
    rules = {}
    for rule in tomllib.loads(toml.read_text("utf-8"))["rules"]:
        if rule["id"].startswith(GITLEAKS_RULES) and "regex" in rule:
            rules["gitleaks:" + rule["id"]] = re.compile(rule["regex"].replace(r"\z", r"\Z"))
    for path in sorted((HERE / "sources").glob("trufflehog-*.go")):
        for number, raw in enumerate(re.findall(r"MustCompile\(`([^`]+)`\)", path.read_text())):
            rules[f"{path.stem}:{number}"] = re.compile(raw.replace(r"\z", r"\Z"))
    return rules


def _secret(match: re.Match[str]) -> str:
    return match.group(1) if match.re.groups and match.group(1) else match.group(0)


def _leaks(rules: dict[str, re.Pattern[str]], line: str) -> list[str]:
    masked = mask_text(line)
    found = []
    for name, rule in rules.items():
        for match in rule.finditer(line):
            secret = _secret(match)
            if len(secret) >= 6 and secret in masked:
                found.append(f"{name}: {line!r} -> {masked!r}")
    return found


def test_the_reference_rules_load() -> None:
    rules = _rules()
    assert sum(name.startswith("gitleaks:") for name in rules) >= 20
    assert sum(name.startswith("trufflehog") for name in rules) >= 8


@pytest.mark.parametrize("seed", range(25))
def test_nothing_a_reference_rule_finds_survives_masking(seed: int) -> None:
    rules = _rules()
    lines = token_lines(seed) + keyword_lines(seed) + [slack_webhook(random.Random(seed))[0]]
    leaks = [leak for line in lines for leak in _leaks(rules, line)]
    assert leaks == []


@pytest.mark.parametrize("seed", range(10))
def test_the_synthetic_tokens_are_realistic(seed: int) -> None:
    # Every generated vendor token is recognised by at least one gitleaks rule, so the
    # corpus exercises real formats rather than shapes made up for this library.
    rules = {k: v for k, v in _rules().items() if k.startswith("gitleaks:")}
    for name, token in tokens(seed):
        # Cards and emails are not vendor tokens; Stripe webhook secrets and the stateless
        # "ghs_APPID_JWT" GitHub format (2026) have no gitleaks rule and are checked
        # against the vendors' pages in test_ground_truth.py instead.
        if name in {"credit_card", "email"} or re.match(r"ghs_[0-9]+_|whsec_", token):
            continue
        assert any(rule.search(token) for rule in rules.values()), (name, token)


def _recorded() -> tuple[dict[str, object], list[list[object]]]:
    document = json.loads((HERE / "fixtures" / "detect_secrets.json").read_text("utf-8"))
    return document, document["findings"]


def test_every_recorded_detect_secrets_finding_is_hidden() -> None:
    document, findings = _recorded()
    assert document["version"] == "1.5.0" and len(findings) > 2000
    cache: dict[tuple[int, str], list[str]] = {}
    plugins = set()
    for seed, kind, number, plugin, start, end, digest in findings:
        key = (int(seed), str(kind))  # type: ignore[call-overload]
        if key not in cache:
            cache[key] = token_lines(key[0]) if kind == "token" else keyword_lines(key[0])
        line = cache[key][int(number)]  # type: ignore[call-overload]
        secret = line[int(start) : int(end)]  # type: ignore[call-overload]
        assert hashlib.sha256(secret.encode()).hexdigest() == digest, "corpus drifted"
        assert secret not in mask_text(line), (plugin, line)
        plugins.add(plugin)
    assert {"AWS Access Key", "JSON Web Token", "Private Key", "Secret Keyword"} <= plugins


def test_detect_secrets_live_on_fresh_seeds() -> None:
    pytest.importorskip("detect_secrets")
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
    from detect_secrets.core.scan import scan_line
    from detect_secrets.settings import transient_settings

    skipped = {"Base64HighEntropyString", "HexHighEntropyString", "IPPublicDetector"}
    plugins = [
        {"name": c.__name__}
        for c in get_mapping_from_secret_type_to_class().values()
        if c.__name__ not in skipped
    ]
    count = 0
    with transient_settings({"plugins_used": plugins}):
        for seed in range(1000, 1010):
            for line in token_lines(seed) + keyword_lines(seed):
                for secret in scan_line(line):
                    count += 1
                    assert secret.secret_value not in mask_text(line), line
    assert count > 1000
