"""Command-line entry point.

``dpdp-scan [path]`` prints a text summary. ``--format`` switches stdout to
JSON, SARIF or Markdown; ``--sarif``, ``--json`` and ``--markdown`` write
those files as well. Nothing printed or written can contain a matched value:
findings carry masked evidence by construction. Exit codes and the baseline
file come in DS-7; until then the exit code is 0 after a completed scan.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from dpdp_scan import __version__
from dpdp_scan.detectors.base import Step
from dpdp_scan.engine import ScanResult, scan_path
from dpdp_scan.output import build_inventory, build_markdown, build_sarif
from dpdp_scan.output.inventory import NOT_LEGAL_ADVICE
from dpdp_scan.walker import WalkOptions

_SEMGREP_NOTES = {
    "missing": "Semgrep is not installed; the rule pack was skipped "
    "(pip install semgrep, or set DPDP_SCAN_SEMGREP).",
    "skipped": "no Python or JavaScript/TypeScript files; the rule pack had nothing to do.",
    "timeout": "Semgrep ran out of time; rule findings are incomplete.",
    "error": "Semgrep reported an error; rule findings may be incomplete.",
}


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
        "--format",
        choices=["text", "json", "sarif", "markdown"],
        default="text",
        help="what to print on stdout (default: text)",
    )
    parser.add_argument("--sarif", metavar="FILE", help="also write a SARIF 2.1.0 file")
    parser.add_argument("--json", metavar="FILE", help="also write the JSON inventory")
    parser.add_argument("--markdown", metavar="FILE", help="also write the Markdown summary")
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


def render_text(result: ScanResult) -> str:
    inv = result.inventory
    out: list[str] = []
    n = len(inv.findings)
    out.append(f"dpdp-scan {__version__}: {result.files_scanned} files scanned, {n} findings")
    if inv.findings:
        out += ["", "By detector:"]
        out += [f"  {det:<28} {n}" for det, n in inv.by_detector.items()]
        out.append("")
        for f in inv.sorted():
            provisions = ", ".join(p.ref for p in f.provisions)
            out.append(
                f"{f.path}:{f.line}:{f.column}  {f.detector_id}  {f.locator or f.evidence}  "
                f"[{f.confidence}]  {provisions}"
            )
    out += ["", NOT_LEGAL_ADVICE]
    return "\n".join(out)


def _write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    min_step = {"low": Step.LOW, "medium": Step.MEDIUM, "high": Step.HIGH}[args.min_confidence]
    root = Path(args.path)
    try:
        result = scan_path(
            root,
            walk_options=WalkOptions(use_git=not args.no_git),
            min_step=min_step,
            rules=not args.no_rules,
        )
    except NotADirectoryError as exc:
        print(f"dpdp-scan: not a directory: {exc}", file=sys.stderr)
        return 2

    sg = result.semgrep
    if sg is not None and sg.status != "ok":
        print(f"dpdp-scan: {_SEMGREP_NOTES[sg.status]}", file=sys.stderr)
        for err in sg.errors[:5]:
            print(f"  {err}", file=sys.stderr)

    root_name = root.resolve().name
    renders = {
        "text": lambda: render_text(result),
        "json": lambda: json.dumps(build_inventory(result), indent=2),
        "sarif": lambda: json.dumps(build_sarif(result, root), indent=2),
        "markdown": lambda: build_markdown(result, root_name),
    }
    if args.sarif:
        _write(args.sarif, renders["sarif"]())
    if args.json:
        _write(args.json, renders["json"]())
    if args.markdown:
        _write(args.markdown, renders["markdown"]())
    print(renders[args.format]())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
