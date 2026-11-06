"""Value detectors: find identifier-shaped text and validate it."""

from __future__ import annotations

from collections.abc import Iterable

from dpdp_scan.config import AllowList
from dpdp_scan.detectors.allowlist import is_allowlisted
from dpdp_scan.detectors.base import Detector, Step
from dpdp_scan.detectors.india import BY_ID, DETECTORS
from dpdp_scan.masking import mask
from dpdp_scan.model import Finding

__all__ = ["BY_ID", "DETECTORS", "scan_text"]


def _line_col(text: str, offset: int, line_starts: list[int]) -> tuple[int, int]:
    # Binary search over line start offsets.
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1, offset - line_starts[lo] + 1


def scan_text(
    text: str,
    path: str,
    detectors: Iterable[Detector] = DETECTORS,
    *,
    min_step: Step = Step.LOW,
    allow: AllowList | None = None,
) -> list[Finding]:
    """Run ``detectors`` over ``text`` and return masked findings for ``path``.

    A UPI id is also an email by shape; when two detectors match the same span
    the more specific one (earlier in ``DETECTORS``) wins. ``allow`` drops
    values the user has accepted by hash, and emails or UPI ids on the user's
    own domains.
    """
    allow = allow or AllowList()
    line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
    taken: list[tuple[int, int]] = []
    findings: list[Finding] = []
    for det in detectors:
        for m in det.pattern.finditer(text):
            start, end = m.span()
            if any(s <= start < e or s < end <= e for s, e in taken):
                continue
            cand = det.validate(m)
            if cand is None or is_allowlisted(det.id, cand.compact):
                continue
            if allow.allows_value(cand.compact) or allow.allows_domain(cand.compact):
                continue
            step = min(det.context_step(text, start, end, cand.step), cand.cap)
            if step < min_step:
                continue
            taken.append((start, end))
            line, col = _line_col(text, start, line_starts)
            findings.append(
                Finding(
                    detector_id=det.id,
                    category=det.category,
                    path=path,
                    line=line,
                    column=col,
                    evidence=mask(cand.compact),
                    confidence=step.to_confidence(),
                    provisions=det.provisions,
                    message=f"{det.label or det.id} ({step.name.lower()} confidence)",
                )
            )
    return sorted(findings, key=lambda f: (f.line, f.column, f.detector_id))
