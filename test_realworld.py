"""
Real-world smoke tests against actual PyPI packages.

Downloads real wheels and runs the full pre-install check suite.
Every package here is a known-good package — any critical failure is a false positive.

Run with:
    pytest test_realworld.py -v                      # all real-world tests
    pytest test_realworld.py -v -k "numpy"           # single package
    pytest test_realworld.py -v --tb=short           # brief output

These tests require network access and are slower than unit tests (~30s total).
They are excluded from the default pytest run via the [tool.pytest.ini_options]
testpaths setting. Run explicitly when making changes to obfuscation detection.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from pipsentinel.checks import (
    fetch_package_metadata,
    check_obfuscated_code,
    check_wheel_record_integrity,
    check_pth_files_in_wheel,
    check_git_tag_divergence,
    check_multi_source_hash_consensus,
)


# ---------------------------------------------------------------------------
# Packages that must never produce a false-positive critical failure.
# Format: (package_name, pinned_version_or_None_for_latest)
# ---------------------------------------------------------------------------

MUST_PASS = [
    # HTTP / networking
    ("requests",            "2.32.3"),
    ("httpx",               "0.28.1"),
    ("urllib3",             "2.3.0"),
    ("certifi",             "2025.1.31"),
    ("charset-normalizer",  "3.4.1"),
    ("idna",                "3.10"),
    # Data / science
    ("numpy",               "1.26.4"),   # the package that caused false positives
    ("pydantic",            "2.10.6"),
    # CLI / formatting
    ("click",               "8.1.8"),
    ("rich",                "13.9.4"),
    ("packaging",           "24.2"),
    # Web
    ("flask",               "3.1.0"),
    ("werkzeug",            "3.1.3"),
    ("jinja2",              "3.1.6"),
    ("markupsafe",          "3.0.2"),
    # Testing
    ("pytest",              "8.3.5"),
    ("pluggy",              "1.5.0"),
    # Build / packaging infra
    ("setuptools",          "75.8.2"),
    ("wheel",               "0.45.1"),
    ("pip",                 "25.0.1"),
    # Async
    ("anyio",               "4.9.0"),
    ("sniffio",             "1.3.1"),
    # Type / data
    ("typing-extensions",   "4.12.2"),
    ("annotated-types",     "0.7.0"),
]


def _download_wheel(meta) -> tuple[bytes, dict] | tuple[None, None]:
    """Download the first .whl found for this package. Returns (bytes, entry) or (None, None)."""
    wheel_entry = next(
        (w for w in meta.wheel_urls if w["filename"].endswith(".whl")), None
    )
    if wheel_entry is None:
        return None, None
    with urllib.request.urlopen(wheel_entry["url"], timeout=60) as r:
        return r.read(), wheel_entry


@pytest.mark.parametrize("package,version", MUST_PASS)
def test_no_false_positive_critical(package, version):
    """
    Run the four deepest checks against a known-good package wheel.
    A critical failure here means a false positive — a regression to fix before publishing.
    """
    try:
        meta = fetch_package_metadata(package, version)
    except Exception as e:
        pytest.skip(f"Could not fetch metadata for {package}: {e}")

    wheel_bytes, wheel_entry = _download_wheel(meta)
    if wheel_bytes is None:
        pytest.skip(f"No wheel available for {package}=={meta.version}")

    checks = [
        check_obfuscated_code(wheel_bytes, wheel_entry["filename"]),
        check_wheel_record_integrity(wheel_bytes, wheel_entry["filename"]),
        check_pth_files_in_wheel(meta),
    ]

    critical = [c for c in checks if not c.passed and c.severity == "critical"]
    assert not critical, (
        f"\n{package}=={meta.version} ({wheel_entry['filename']}) has FALSE POSITIVE critical failures:\n"
        + "\n".join(f"  [{c.name}] {c.message}" for c in critical)
    )


@pytest.mark.parametrize("package,version", MUST_PASS)
def test_git_tag_exists(package, version):
    """
    Every package in MUST_PASS should have a git tag matching its PyPI version.
    A failure here means the check logic is broken, or the package genuinely has no tag.
    Allowed to warn — only fails if severity == critical.
    """
    try:
        meta = fetch_package_metadata(package, version)
    except Exception as e:
        pytest.skip(f"Could not fetch metadata: {e}")

    result = check_git_tag_divergence(meta)

    # Some packages (like certifi) use date-based tags — assert not critical
    assert result.severity != "critical", (
        f"{package}=={meta.version} git tag check is critical: {result.message}"
    )


@pytest.mark.parametrize("package,version", MUST_PASS)
def test_hash_consensus(package, version):
    """
    Multi-source hash must agree for every package.
    Disagreement = CDN or API tampering, which is always a real failure (not a false positive).
    """
    try:
        meta = fetch_package_metadata(package, version)
    except Exception as e:
        pytest.skip(f"Could not fetch metadata: {e}")

    result = check_multi_source_hash_consensus(meta)
    assert result.passed, (
        f"{package}=={meta.version} hash consensus failed: {result.message}"
    )
