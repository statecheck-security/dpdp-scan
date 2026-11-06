"""Turn Semgrep JSON results into :class:`~dpdp_scan.model.Finding` objects.

Semgrep hands back the matched source text. That text is code, usually a
field access such as ``user.aadhaar``, but it may carry a literal value, so
nothing from it reaches a finding unmasked: the locator is the bound
metavariable's text with digit runs and email addresses masked and the whole
thing truncated, and the message is the rule's own static text.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from dpdp_scan.masking import DECLARED, mask
from dpdp_scan.model import Category, Confidence, Finding, Provision

#: Value shapes masked out of matched code before it becomes a locator. Order
#: matters: GSTIN before PAN (a GSTIN contains a PAN), UPI before plain emails.
_VALUE_SHAPES = (
    re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"),  # GSTIN
    re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),  # PAN
    re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*"),  # email or UPI
    re.compile(r"\d{6,}"),  # Aadhaar, mobile, account numbers, anything long
)
_LOCATOR_MAX = 80
#: Metavariables, in order of preference, whose text names the personal data.
#: Recent Semgrep releases omit ``metavars`` from JSON; then the matched
#: source line is used instead.
_LOCATOR_VARS = ("$X", "$EXPR", "$FIELD", "$KEY", "$ARG")

_CATEGORIES = {c.value: c for c in Category}
_CONFIDENCES = {c.value: c for c in Confidence}


def sanitise(text: str) -> str:
    for shape in _VALUE_SHAPES:
        text = shape.sub(lambda m: mask(m.group(0)), text)
    text = " ".join(text.split())
    return text[:_LOCATOR_MAX]


def _relpath(path: str, root_posix: str) -> str:
    p = path.replace("\\", "/")
    if p.startswith(root_posix + "/"):
        p = p[len(root_posix) + 1 :]
    return p


def _read_span(
    path: Path, start: dict[str, Any], end: dict[str, Any], cache: dict[Path, list[str]]
) -> str:
    """The matched source text, read from the file. Semgrep's own ``lines``
    field says "requires login" unless the CLI is signed in, so the span is
    reconstructed from the positions it does report. Empty on any failure."""
    try:
        if path not in cache:
            cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
        lines = cache[path]
        s_line = int(start.get("line", 0) or 0)
        e_line = int(end.get("line", s_line) or s_line)
        s_col = max(int(start.get("col", 1) or 1) - 1, 0)
        e_col = int(end.get("col", 0) or 0) - 1
        if s_line < 1 or s_line > len(lines):
            return ""
        first = lines[s_line - 1]
        if e_line == s_line and e_col > s_col:
            return first[s_col:e_col]
        return first[s_col:]
    except (OSError, ValueError):
        return ""


def to_findings(results: list[dict[str, Any]], root_posix: str = "") -> list[Finding]:
    findings: list[Finding] = []
    cache: dict[Path, list[str]] = {}
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
        end = r.get("end", {}) if isinstance(r.get("end"), dict) else {}
        path = _relpath(str(r.get("path", "")), root_posix)
        if not path or PurePosixPath(path).is_absolute():
            continue
        lines_field = extra.get("lines")
        if not locator and isinstance(lines_field, str) and lines_field != "requires login":
            locator = sanitise(lines_field)
        if not locator and root_posix:
            locator = sanitise(_read_span(Path(root_posix) / path, start, end, cache))
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
