"""Command-line entry point.

``dpdp-scan [path]`` scans and prints a text summary. ``--format`` switches
stdout to JSON, SARIF or Markdown; ``--sarif``, ``--json`` and ``--markdown``
write those files as well. Nothing printed or written can contain a matched
value: findings carry masked evidence by construction.

Exit codes:

- ``0``: the scan completed and no finding is at or above ``--fail-on`` (or
  ``--fail-on`` is ``none``, the default).
- ``1``: the scan completed and at least one finding is at or above
  ``--fail-on``, or is in a ``--fail-on-category`` category.
- ``2``: the scan did not complete: bad arguments, unreadable path, invalid
  config or baseline.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from dpdp_scan import __version__
from dpdp_scan.baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from dpdp_scan.config import Config, ConfigError, load_config, value_hash
from dpdp_scan.detectors.base import Step, compact_value
from dpdp_scan.engine import STEP_FOR, ScanResult, scan_path
from dpdp_scan.model import Category
from dpdp_scan.output import build_inventory, build_markdown, build_sarif
from dpdp_scan.output.inventory import NOT_LEGAL_ADVICE
from dpdp_scan.walker import WalkOptions

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_STEPS = {"none": None, "low": Step.LOW, "medium": Step.MEDIUM, "high": Step.HIGH}
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
        epilog=NOT_LEGAL_ADVICE + " Exit codes: 0 clean, 1 findings at or above --fail-on, "
        "2 the scan did not complete.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="repository or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="config file (default: .dpdp-scan.yml in the scanned path, if present)",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="low",
        help="drop findings below this confidence (default: low, keep everything)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high"],
        default=None,
        help="exit 1 if any finding is at or above this confidence "
        "(default: the config's fail_on, else none)",
    )
    parser.add_argument(
        "--fail-on-category",
        metavar="CATS",
        default="",
        help="comma-separated categories that exit 1 at any confidence, e.g. identity,age_dob",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="drop findings recorded in this baseline (default: the config's baseline)",
    )
    parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="record every current finding's fingerprint to FILE and exit 0",
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
    parser.add_argument(
        "--hash-value",
        metavar="VALUE",
        help="print the sha256 of VALUE for allow.values_sha256 in the config, and exit",
    )
    return parser


def render_text(result: ScanResult) -> str:
    inv = result.inventory
    out: list[str] = []
    n = len(inv.findings)
    out.append(f"dpdp-scan {__version__}: {result.files_scanned} files scanned, {n} findings")
    if result.suppressed:
        out.append(f"  ({result.suppressed} accepted by the baseline)")
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


def _parse_categories(raw: str) -> set[Category]:
    cats: set[Category] = set()
    for item in (x.strip() for x in raw.split(",") if x.strip()):
        try:
            cats.add(Category(item))
        except ValueError:
            valid = ", ".join(c.value for c in Category)
            raise ConfigError(f"unknown category '{item}' (valid: {valid})") from None
    return cats


def should_fail(result: ScanResult, threshold: Step | None, categories: set[Category]) -> bool:
    for f in result.inventory.findings:
        if threshold is not None and STEP_FOR[f.confidence] >= threshold:
            return True
        if f.category in categories:
            return True
    return False


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.hash_value is not None:
        print(value_hash(compact_value(args.hash_value)))
        return EXIT_CLEAN

    root = Path(args.path)
    try:
        if not root.is_dir():
            raise NotADirectoryError(root)
        config: Config = load_config(root, args.config)
        categories = _parse_categories(args.fail_on_category)
    except NotADirectoryError as exc:
        print(f"dpdp-scan: not a directory: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ConfigError as exc:
        print(f"dpdp-scan: config error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    min_step = _STEPS[args.min_confidence]
    assert min_step is not None
    result = scan_path(
        root,
        walk_options=WalkOptions(use_git=not args.no_git),
        min_step=min_step,
        rules=not args.no_rules,
        config=config,
    )

    sg = result.semgrep
    if sg is not None and sg.status != "ok":
        print(f"dpdp-scan: {_SEMGREP_NOTES[sg.status]}", file=sys.stderr)
        for err in sg.errors[:5]:
            print(f"  {err}", file=sys.stderr)

    if args.write_baseline:
        n = write_baseline(Path(args.write_baseline), result.inventory)
        print(f"dpdp-scan: wrote {n} fingerprints to {args.write_baseline}", file=sys.stderr)
        return EXIT_CLEAN

    baseline_path = args.baseline or (str(root / config.baseline) if config.baseline else "")
    if baseline_path:
        try:
            baseline = load_baseline(Path(baseline_path))
        except BaselineError as exc:
            print(f"dpdp-scan: baseline error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        result.inventory, result.suppressed = apply_baseline(result.inventory, baseline)

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

    threshold = _STEPS[args.fail_on] if args.fail_on is not None else config.fail_on
    if should_fail(result, threshold, categories):
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
