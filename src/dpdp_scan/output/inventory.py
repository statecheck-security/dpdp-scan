"""JSON inventory: what personal data the repository handles, and where.

Shaped to seed a data map or a record of processing: ``data_map`` groups the
declared fields by the table, model or schema they live in; ``values`` lists
where literal identifiers were found; ``rules`` lists the code patterns. Every
entry carries the provisions it engages so the next step (purpose, retention,
safeguards per field) has its legal pointers ready.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from dpdp_scan import __version__
from dpdp_scan.catalogue import CATALOGUE_VERSION, CATEGORY_LABELS, rule_info
from dpdp_scan.engine import ScanResult
from dpdp_scan.model import Category, Finding

NOT_LEGAL_ADVICE = (
    "dpdp-scan reports where personal data appears and which obligation it touches. "
    "It is not legal advice and gives no compliance verdict."
)


def _kind(f: Finding) -> str:
    if f.detector_id.startswith("schema_"):
        return "declared"
    if f.detector_id.startswith("rule:"):
        return "rule"
    return "value"


def _entry(f: Finding) -> dict[str, Any]:
    return {
        "detector": f.detector_id,
        "category": str(f.category),
        "confidence": str(f.confidence),
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "locator": f.locator,
        "evidence": f.evidence,
        "provisions": [p.ref for p in f.provisions],
    }


def build_inventory(result: ScanResult) -> dict[str, Any]:
    findings = result.inventory.sorted()
    by_conf: dict[str, int] = defaultdict(int)
    for f in findings:
        by_conf[str(f.confidence)] += 1

    # Declared fields grouped by container: the seed of a data map.
    containers: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if _kind(f) != "declared":
            continue
        container, _, field = f.locator.rpartition(".")
        containers[(container or f.locator, f.path)].append(
            {
                "field": field or f.locator,
                "category": str(f.category),
                "confidence": str(f.confidence),
                "line": f.line,
                "provisions": [p.ref for p in f.provisions],
            }
        )
    data_map = [
        {"container": c, "path": p, "fields": fields}
        for (c, p), fields in sorted(containers.items())
    ]

    categories = []
    for cat in Category:
        members = [f for f in findings if f.category == cat]
        if not members:
            continue
        refs: list[str] = []
        for f in members:
            for p in f.provisions:
                if p.ref not in refs:
                    refs.append(p.ref)
        categories.append(
            {
                "category": str(cat),
                "label": CATEGORY_LABELS[cat],
                "count": len(members),
                "provisions": refs,
                "detectors": sorted({f.detector_id for f in members}),
            }
        )

    sg = result.semgrep
    return {
        "tool": "dpdp-scan",
        "version": __version__,
        "catalogue_version": CATALOGUE_VERSION,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_legal_advice": NOT_LEGAL_ADVICE,
        "summary": {
            "files_scanned": result.files_scanned,
            "files_unreadable": result.files_unreadable,
            "findings": len(findings),
            "by_category": result.inventory.by_category,
            "by_detector": result.inventory.by_detector,
            "by_confidence": dict(sorted(by_conf.items())),
            "semgrep": {"status": sg.status, "errors": sg.errors[:10]} if sg else {"status": "off"},
        },
        "categories": categories,
        "data_map": data_map,
        "values": [_entry(f) for f in findings if _kind(f) == "value"],
        "rules": [
            {**_entry(f), "rule": rule_info(f.detector_id).name}
            for f in findings
            if _kind(f) == "rule"
        ],
    }
