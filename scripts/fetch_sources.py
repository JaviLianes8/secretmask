"""Fetch the vendor documentation and reference rule sets the ground-truth tests read.

    python scripts/fetch_sources.py           # fetch and rewrite the manifest
    python scripts/fetch_sources.py --check   # fail if a source changed since the manifest

The copies land in ``tests/sources/`` (git-ignored: third-party text is never committed
or shipped). ``tests/sources/MANIFEST.json`` is tracked and records, for each file, the
URL, the fetch date, size, SHA-256 and licence. Tests that read a copy skip when it is
missing. Vendor pages are live documents; the rule sets are pinned to a commit.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "tests" / "sources"
RFC = "https://www.rfc-editor.org/rfc"
GITLEAKS = (
    "https://raw.githubusercontent.com/gitleaks/gitleaks/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
)
TRUFFLEHOG = (
    "https://raw.githubusercontent.com/trufflesecurity/trufflehog/"
    "31d730383da3a2a71735410240ab9416f8f0eb54/pkg/detectors"
)
GITHUB_DOC = (
    "https://docs.github.com/api/article/body?pathname=/en/authentication/"
    "keeping-your-account-and-data-secure/about-authentication-to-github"
)
SOURCES = {
    "aws-iam-identifiers.html": (
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html",
        "CC-BY-SA-4.0",
    ),
    "github-authentication.md": (GITHUB_DOC, "CC-BY-4.0"),
    "stripe-keys.md": ("https://docs.stripe.com/keys.md", "Stripe documentation"),
    "stripe-testing.md": ("https://docs.stripe.com/testing.md", "Stripe documentation"),
    "stripe-webhook-signature.md": (
        "https://docs.stripe.com/webhooks/signature.md",
        "Stripe documentation",
    ),
    "slack-tokens.html": ("https://docs.slack.dev/authentication/tokens", "Slack documentation"),
    "google-api-keys.html": (
        "https://cloud.google.com/docs/authentication/api-keys",
        "CC-BY-4.0",
    ),
    "rfc3986.txt": (f"{RFC}/rfc3986.txt", "IETF Trust"),
    "rfc4880.txt": (f"{RFC}/rfc4880.txt", "IETF Trust"),
    "rfc6750.txt": (f"{RFC}/rfc6750.txt", "IETF Trust"),
    "rfc7468.txt": (f"{RFC}/rfc7468.txt", "IETF Trust"),
    "rfc7519.txt": (f"{RFC}/rfc7519.txt", "IETF Trust"),
    "rfc7617.txt": (f"{RFC}/rfc7617.txt", "IETF Trust"),
    "gitleaks.toml": (f"{GITLEAKS}/config/gitleaks.toml", "MIT"),
    "trufflehog-aws.go": (f"{TRUFFLEHOG}/aws/access_keys/accesskey.go", "AGPL-3.0"),
    "trufflehog-github.go": (f"{TRUFFLEHOG}/github/v2/github.go", "AGPL-3.0"),
    "trufflehog-openai.go": (f"{TRUFFLEHOG}/openai/openai.go", "AGPL-3.0"),
    "trufflehog-privatekey.go": (f"{TRUFFLEHOG}/privatekey/privatekey.go", "AGPL-3.0"),
    "trufflehog-slack.go": (f"{TRUFFLEHOG}/slack/slack.go", "AGPL-3.0"),
    "trufflehog-slackwebhook.go": (f"{TRUFFLEHOG}/slackwebhook/slackwebhook.go", "AGPL-3.0"),
    "trufflehog-stripe.go": (f"{TRUFFLEHOG}/stripe/stripe.go", "AGPL-3.0"),
}


def _fetch(url: str) -> bytes:
    headers = {"User-Agent": "Mozilla/5.0 (secretmask-sources)", "Accept-Language": "en-US,en"}
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return bytes(response.read())


def main() -> int:
    ROOT.mkdir(parents=True, exist_ok=True)
    manifest_path = ROOT / "MANIFEST.json"
    check = "--check" in sys.argv
    old = json.loads(manifest_path.read_text("utf-8")) if manifest_path.is_file() else {}
    manifest = {}
    changed = 0
    for name, (url, licence) in SOURCES.items():
        data = _fetch(url)
        digest = hashlib.sha256(data).hexdigest()
        if old.get(name, {}).get("sha256") != digest:
            changed += 1
            print(f"{name}: differs from the manifest")
        (ROOT / name).write_bytes(data)
        manifest[name] = {
            "url": url,
            "fetched": datetime.date.today().isoformat(),
            "size": len(data),
            "sha256": digest,
            "licence": licence,
        }
        print(f"{name}: {len(data)} bytes")
    if check:
        return 1 if changed else 0
    text = json.dumps(manifest, indent=1, sort_keys=True) + "\n"
    manifest_path.write_text(text, "utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
