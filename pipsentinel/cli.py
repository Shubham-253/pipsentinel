"""
CLI entry point for pipsentinel.

Usage:
    pipsentinel install requests
    pipsentinel install numpy==1.26.4
    pipsentinel install -r requirements.txt
    pipsentinel sync                         # check uv.lock packages then run uv sync
    pipsentinel audit                        # post-install site-packages scan
    pipsentinel check somepackage==1.0.0     # check only, don't install
    pipsentinel check requests --json        # output JSON report
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path

from .checks import fetch_package_metadata, check_git_tag_divergence, check_pth_files_in_wheel, check_pypi_provenance, check_post_install_pth
from .installer import safe_install, safe_install_requirements
from .report import SecurityReport


def cmd_install(args: argparse.Namespace) -> int:
    # requirements file mode
    if args.requirements:
        reports = safe_install_requirements(
            args.requirements,
            force=args.force,
            quiet=args.quiet,
        )
        failed = [r for r in reports if not r.safe_to_install]
        return 1 if failed else 0

    pkg = args.package
    if not pkg:
        print("❌ Provide a package name or use -r <requirements.txt>")
        return 1

    version = None
    if "==" in pkg:
        pkg, version = pkg.split("==", 1)

    report = safe_install(
        pkg,
        version=version,
        force=args.force,
        quiet=args.quiet,
    )

    if args.json:
        print(report.to_json())

    return 0 if report.safe_to_install else 1


def cmd_sync(args: argparse.Namespace) -> int:
    """Check all packages in uv.lock, then run uv sync if all pass."""
    lock_file = Path(args.lockfile)
    if not lock_file.exists():
        print(f"❌ Lock file not found: {lock_file}")
        print("   Run 'uv lock' first to generate it.")
        return 1

    with open(lock_file, "rb") as f:
        lock_data = tomllib.load(f)

    packages = [
        (pkg["name"], pkg["version"])
        for pkg in lock_data.get("package", [])
        if pkg.get("source", {}).get("registry")  # only PyPI packages
    ]

    if not packages:
        print("⚠️  No PyPI packages found in lock file.")
        return 0

    print(f"\n🔒 pipsentinel: auditing {len(packages)} package(s) from {lock_file} before uv sync\n")

    blocked = []
    for name, version in packages:
        try:
            meta = fetch_package_metadata(name, version)
        except Exception as e:
            print(f"  ⚠️  Could not fetch metadata for {name}=={version}: {e}")
            continue

        report = SecurityReport(package=meta.name, version=meta.version)
        report.results = [
            check_git_tag_divergence(meta),
            check_pth_files_in_wheel(meta),
            check_pypi_provenance(meta),
        ]

        if not args.quiet:
            status = "✅" if report.safe_to_install else "🚨"
            print(f"  {status} {name}=={version} — {report.risk_level}")

        if not report.safe_to_install:
            blocked.append(f"{name}=={version}")

    print()

    if blocked and not args.force:
        print(f"🚨 uv sync BLOCKED — {len(blocked)} package(s) failed checks:")
        for b in blocked:
            print(f"   • {b}")
        print("\n   Resolve the above before syncing.")
        return 1

    print("✅ All checks passed. Running uv sync ...\n")
    result = subprocess.run(["uv", "sync"] + (args.uv_args or []))
    return result.returncode


def cmd_check(args: argparse.Namespace) -> int:
    pkg = args.package
    version = None
    if "==" in pkg:
        pkg, version = pkg.split("==", 1)

    print(f"\n🔍 pipsentinel: checking {pkg}" + (f"=={version}" if version else " (latest)") + " ...")

    try:
        meta = fetch_package_metadata(pkg, version)
    except Exception as e:
        print(f"❌ {e}")
        return 1

    report = SecurityReport(package=meta.name, version=meta.version)
    report.results = [
        check_git_tag_divergence(meta),
        check_pth_files_in_wheel(meta),
        check_pypi_provenance(meta),
    ]

    if args.json:
        print(report.to_json())
    else:
        print(report.summary())

    return 0 if report.safe_to_install else 1


def cmd_audit(_args: argparse.Namespace) -> int:
    print("\n🔎 pipsentinel: auditing site-packages for suspicious .pth files ...\n")
    result = check_post_install_pth()
    print(result)
    if not result.passed:
        print("\nDetail:")
        for f in result.detail.get("suspicious_files", []):
            print(f"  🚨 {f['path']}")
            for line in f.get("import_lines", []):
                print(f"       import line: {line[:120]}")
    return 0 if result.passed else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pipsentinel",
        description="Hack-proof pip: supply chain checks before every install.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # install
    p_install = sub.add_parser("install", help="Check and install a package securely")
    p_install.add_argument("package", nargs="?", help="Package name, e.g. requests or litellm==1.82.6")
    p_install.add_argument("-r", "--requirements", metavar="FILE", help="Requirements file (e.g. requirements.txt)")
    p_install.add_argument("--force", action="store_true", help="Install even if critical checks fail")
    p_install.add_argument("--quiet", "-q", action="store_true")
    p_install.add_argument("--json", action="store_true", help="Output JSON report")

    # sync (uv)
    p_sync = sub.add_parser("sync", help="Check uv.lock packages then run uv sync")
    p_sync.add_argument("--lockfile", default="uv.lock", metavar="FILE", help="Path to uv.lock (default: uv.lock)")
    p_sync.add_argument("--force", action="store_true", help="Run uv sync even if checks fail")
    p_sync.add_argument("--quiet", "-q", action="store_true")
    p_sync.add_argument("uv_args", nargs=argparse.REMAINDER, help="Extra args passed to uv sync")

    # check (no install)
    p_check = sub.add_parser("check", help="Run security checks without installing")
    p_check.add_argument("package")
    p_check.add_argument("--json", action="store_true")

    # audit (post-install scan)
    sub.add_parser("audit", help="Scan site-packages for suspicious .pth files")

    args = parser.parse_args()

    dispatch = {
        "install": cmd_install,
        "sync": cmd_sync,
        "check": cmd_check,
        "audit": cmd_audit,
    }

    sys.exit(dispatch[args.command](args))


if __name__ == "__main__":
    main()
