"""SARIF 2.1.0 output for GitHub code scanning and other SARIF viewers.

Anchoring: every result has a physical location with a repo-relative,
forward-slash URI and ``uriBaseId: "%SRCROOT%"``. GitHub resolves that
against the checkout, so the scan can run from any working directory. When
``GITHUB_WORKSPACE`` is set, ``originalUriBaseIds`` records it; otherwise the
scanned root is recorded. The URI conversion is ported from Paranoid.

Nothing in the document carries a raw value: messages are built from the
catalogue text plus the finding's masked evidence or its locator.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import Any

from dpdp_scan import __version__
from dpdp_scan.catalogue import CATALOGUE_VERSION, RuleInfo, catalogue, rule_info
from dpdp_scan.engine import ScanResult
from dpdp_scan.masking import DECLARED
from dpdp_scan.model import Confidence, Finding, fingerprint

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/statecheck-security/dpdp-scan"

_LEVEL = {Confidence.HIGH: "warning", Confidence.MEDIUM: "warning", Confidence.LOW: "note"}


def to_sarif_uri(path: PurePath | str) -> str:
    """Forward-slash form of a path for ``artifactLocation.uri``."""
    if isinstance(path, PurePath):
        return path.as_posix()
    return path.replace("\\", "/")


def _file_uri(path: Path) -> str:
    uri = path.resolve().as_uri()
    return uri if uri.endswith("/") else uri + "/"


def _rule_descriptor(info: RuleInfo, index: int) -> dict[str, Any]:
    refs = ", ".join(p.ref for p in info.provisions)
    help_text = info.description
    if info.remediation:
        help_text += f"\n\nWhat to do: {info.remediation}"
    if refs:
        help_text += f"\n\nDPDP Act / Rules: {refs}"
    help_text += "\n\nThis is a pointer for engineers, not legal advice."
    props: dict[str, Any] = {
        "category": str(info.category),
        "dpdpa": [p.ref for p in info.provisions],
        "tags": ["privacy", "dpdpa", str(info.category)],
    }
    return {
        "id": info.id,
        "name": info.name.replace(" ", ""),
        "shortDescription": {"text": info.name},
        "fullDescription": {"text": info.description},
        "help": {"text": help_text},
        "helpUri": f"{INFORMATION_URI}#rules",
        "defaultConfiguration": {"level": "warning"},
        "properties": props,
    }


def _message(f: Finding, info: RuleInfo) -> str:
    where = f.locator if f.locator else f"masked value {f.evidence}"
    if f.evidence == DECLARED and not f.locator:
        where = "see location"
    text = f"{info.name}: {where} ({f.confidence} confidence)."
    refs = ", ".join(p.ref for p in f.provisions or info.provisions)
    if refs:
        text += f" Engages {refs}."
    return text


def _result(f: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    info = rule_info(f.detector_id)
    region: dict[str, Any] = {"startLine": max(f.line, 1)}
    if f.column > 0:
        region["startColumn"] = f.column
    return {
        "ruleId": f.detector_id,
        "ruleIndex": rule_index[f.detector_id],
        "level": _LEVEL[f.confidence],
        "message": {"text": _message(f, info)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": to_sarif_uri(f.path), "uriBaseId": "%SRCROOT%"},
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {"dpdpScanFinding/v1": fingerprint(f)},
        "properties": {
            "category": str(f.category),
            "confidence": str(f.confidence),
            "dpdpa": [p.ref for p in f.provisions],
            "locator": f.locator,
            "evidence": f.evidence,
        },
    }


def build_sarif(result: ScanResult, root: Path | str) -> dict[str, Any]:
    findings = result.inventory.sorted()
    used_ids = sorted({f.detector_id for f in findings})
    cat = catalogue()
    rules = [_rule_descriptor(cat.get(rid) or rule_info(rid), i) for i, rid in enumerate(used_ids)]
    rule_index = {rid: i for i, rid in enumerate(used_ids)}

    workspace = os.environ.get("GITHUB_WORKSPACE", "").strip()
    base_path = Path(workspace) if workspace else Path(root)

    notifications: list[dict[str, Any]] = []
    sg = result.semgrep
    if sg is not None and sg.status != "ok":
        notifications.append(
            {
                "level": "warning" if sg.status in ("timeout", "error") else "note",
                "message": {"text": f"Semgrep rule pack status: {sg.status}."},
                "descriptor": {"id": "dpdp-scan/semgrep-status"},
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dpdp-scan",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                        "properties": {"catalogueVersion": CATALOGUE_VERSION},
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": _file_uri(base_path)}},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "columnKind": "utf16CodeUnits",
                "results": [_result(f, rule_index) for f in findings],
                "properties": {
                    "filesScanned": result.files_scanned,
                    "semgrepStatus": sg.status if sg else "off",
                    "notLegalAdvice": True,
                },
            }
        ],
    }
