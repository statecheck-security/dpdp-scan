"""Command-line entry point.

Until DS-6 and DS-7 land (SARIF, JSON inventory, baseline, ``--fail-on``), the
CLI prints a masked text summary and exits 0. Nothing it prints can contain a
matched value: findings carry masked evidence by construction.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from dpdp_scan import __version__
from dpdp_scan.detectors.base import Step
from dpdp_scan.engine import scan_path
from dpdp_scan.walker import WalkOptions

NOT_LEGAL_ADVICE = (
    "dpdp-scan reports where personal data appears and which obligation it "
    "touches. It is not legal advice and gives no compliance verdict."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dpdp-scan",
        description=(
            "Find Indian personal data (Aadhaar, PAN, GSTIN, UPI, IFSC, mobile) in "
            "code, schemas, fixtures and logs."
        ),
        epilog=NOT_LEGAL_ADVICE,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="repository or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="low",
        help="drop findings below this confidence (default: low, keep everything)",
    )
    parser.add_argument(
        "--no-git",
        action="store_true",
        help="do not ask git for the file list; walk the tree and ignore .gitignore",
    )
    parser.add_argument(
        "--no-rules",
        action="store_true",
        help="skip the Semgrep rule pack (logs, analytics SDKs, age gates)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    min_step = {"low": Step.LOW, "medium": Step.MEDIUM, "high": Step.HIGH}[args.min_confidence]
    try:
        result = scan_path(
            args.path,
            walk_options=WalkOptions(use_git=not args.no_git),
            min_step=min_step,
            rules=not args.no_rules,
        )
    except NotADirectoryError as exc:
        print(f"dpdp-scan: not a directory: {exc}", file=sys.stderr)
        return 2

    sg = result.semgrep
    if sg is not None and sg.status != "ok":
        notes = {
            "missing": "Semgrep is not installed; the rule pack was skipped "
            "(pip install semgrep, or set DPDP_SCAN_SEMGREP).",
            "skipped": "no Python or JavaScript/TypeScript files; the rule pack had nothing to do.",
            "timeout": "Semgrep ran out of time; rule findings are incomplete.",
            "error": "Semgrep reported an error; rule findings may be incomplete.",
        }
        print(f"dpdp-scan: {notes[sg.status]}", file=sys.stderr)
        for err in sg.errors[:5]:
            print(f"  {err}", file=sys.stderr)

    inv = result.inventory
    n = len(inv.findings)
    print(f"dpdp-scan {__version__}: {result.files_scanned} files scanned, {n} findings")
    if inv.findings:
        print()
        print("By detector:")
        for det, n in inv.by_detector.items():
            print(f"  {det:<20} {n}")
        print()
        for f in inv.sorted():
            provisions = ", ".join(p.ref for p in f.provisions)
            print(
                f"{f.path}:{f.line}:{f.column}  {f.detector_id}  {f.locator or f.evidence}  "
                f"[{f.confidence}]  {provisions}"
            )
    print()
    print(NOT_LEGAL_ADVICE)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
