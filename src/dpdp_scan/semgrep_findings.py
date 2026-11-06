"""Turn Semgrep JSON results into :class:`~dpdp_scan.model.Finding` objects.

Semgrep hands back the matched source text. That text is code, usually a
field access such as ``user.aadhaar``, but it may carry a literal value, so
nothing from it reaches a finding unmasked: the locator is the bound
metavariable's text with digit runs and email addresses masked and the whole
thing truncated, and the message is the rule's own static text.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from dpdp_scan.masking import DECLARED, mask
from dpdp_scan.model import Category, Confidence, Finding, Provision

_DIGIT_RUN = re.compile(r"\d{6,}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_LOCATOR_MAX = 80
#: Metavariables, in order of preference, whose text names the personal data.
_LOCATOR_VARS = ("$X", "$EXPR", "$FIELD", "$KEY", "$ARG")

_CATEGORIES = {c.value: c for c in Category}
_CONFIDENCES = {c.value: c for c in Confidence}


def sanitise(text: str) -> str:
    text = _EMAIL.sub(lambda m: mask(m.group(0)), text)
    text = _DIGIT_RUN.sub(lambda m: mask(m.group(0)), text)
    text = " ".join(text.split())
    return text[:_LOCATOR_MAX]


def _relpath(path: str, root_posix: str) -> str:
    p = path.replace("\\", "/")
    if p.startswith(root_posix + "/"):
        p = p[len(root_posix) + 1 :]
    return p


def to_findings(results: list[dict[str, Any]], root_posix: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        extra = r.get("extra", {}) if isinstance(r.get("extra"), dict) else {}
        meta = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}
        rule_id = str(r.get("check_id", "")).split(".")[-1]
        category = _CATEGORIES.get(str(meta.get("category", "")), Category.OTHER)
        confidence = _CONFIDENCES.get(str(meta.get("confidence", "")), Confidence.LOW)
        provisions = tuple(
            Provision(str(ref), str(meta.get("provision_notes", {}).get(ref, "")))
            for ref in meta.get("dpdpa", [])
            if isinstance(meta.get("provision_notes", {}), dict)
        ) or tuple(Provision(str(ref)) for ref in meta.get("dpdpa", []))
        metavars = extra.get("metavars", {}) if isinstance(extra.get("metavars"), dict) else {}
        locator = ""
        for var in _LOCATOR_VARS:
            mv = metavars.get(var)
            if isinstance(mv, dict) and isinstance(mv.get("abstract_content"), str):
                locator = sanitise(mv["abstract_content"])
                break
        start = r.get("start", {}) if isinstance(r.get("start"), dict) else {}
        path = _relpath(str(r.get("path", "")), root_posix)
        if not path or PurePosixPath(path).is_absolute():
            continue
        findings.append(
            Finding(
                detector_id=f"rule:{rule_id}",
                category=category,
                path=path,
                line=int(start.get("line", 0) or 0),
                column=int(start.get("col", 0) or 0),
                evidence=DECLARED,
                confidence=confidence,
                provisions=provisions,
                message=" ".join(str(extra.get("message", "")).split())[:300],
                locator=locator,
            )
        )
    return findings
