"""Command-line entry point.

v0.0.1 is a name-holding release: it parses arguments and reports that the
scanner is not built yet. The real pipeline lands in DS-2 to DS-7 of the plan.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from dpdp_scan import __version__

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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(
        f"dpdp-scan {__version__}: the scanner is not built yet; nothing was read "
        f"under {args.path!r}.",
        file=sys.stderr,
    )
    print(NOT_LEGAL_ADVICE, file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
