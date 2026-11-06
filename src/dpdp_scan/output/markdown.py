"""Markdown summary grouped by category, with the obligation each one touches."""

from __future__ import annotations

from collections import Counter

from dpdp_scan import __version__
from dpdp_scan.catalogue import CATALOGUE_VERSION, CATEGORY_LABELS, rule_info
from dpdp_scan.engine import ScanResult
from dpdp_scan.model import Category, Finding
from dpdp_scan.output.inventory import NOT_LEGAL_ADVICE

_MAX_ROWS_PER_CATEGORY = 25


def _where(f: Finding) -> str:
    loc = f"`{f.path}:{f.line}`" if f.line else f"`{f.path}`"
    what = f"`{f.locator}`" if f.locator else f"`{f.evidence}`"
    return f"{loc} {what}"


def build_markdown(result: ScanResult, root_name: str = "") -> str:
    findings = result.inventory.sorted()
    lines: list[str] = []
    title = "dpdp-scan report" + (f": {root_name}" if root_name else "")
    lines += [f"# {title}", ""]
    lines += [
        f"{result.files_scanned} files scanned, {len(findings)} findings. "
        f"dpdp-scan {__version__}, catalogue {CATALOGUE_VERSION}.",
        "",
    ]
    sg = result.semgrep
    if sg is not None and sg.status != "ok":
        lines += [f"> Rule pack: Semgrep status `{sg.status}`; rule findings may be absent.", ""]

    if not findings:
        lines += ["No personal data found by the value detectors, schema classifier or rules.", ""]
    else:
        lines += ["## Summary", "", "| Category | Findings | Engages |", "|---|---:|---|"]
        for cat in Category:
            members = [f for f in findings if f.category == cat]
            if not members:
                continue
            refs: list[str] = []
            for f in members:
                for p in f.provisions:
                    if p.ref not in refs:
                        refs.append(p.ref)
            lines.append(f"| {CATEGORY_LABELS[cat]} | {len(members)} | {', '.join(refs)} |")
        lines.append("")

        for cat in Category:
            members = [f for f in findings if f.category == cat]
            if not members:
                continue
            lines += [f"## {CATEGORY_LABELS[cat]}", ""]
            by_rule = Counter(f.detector_id for f in members)
            for rid, n in sorted(by_rule.items()):
                info = rule_info(rid)
                lines.append(f"**{info.name}** ({n}). {info.description}")
                if info.remediation:
                    lines.append(f"What to do: {info.remediation}")
                lines.append("")
            lines += ["| Where | Confidence |", "|---|---|"]
            for f in members[:_MAX_ROWS_PER_CATEGORY]:
                lines.append(f"| {_where(f)} | {f.confidence} |")
            if len(members) > _MAX_ROWS_PER_CATEGORY:
                lines.append(f"| … {len(members) - _MAX_ROWS_PER_CATEGORY} more | |")
            lines.append("")

    lines += ["---", "", f"*{NOT_LEGAL_ADVICE}*", ""]
    return "\n".join(lines)
