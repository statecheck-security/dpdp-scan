"""Baseline: accept the findings a repository already has.

The gitleaks shape. ``--write-baseline`` records a fingerprint for every
current finding; ``--baseline`` drops findings whose fingerprint is recorded
so CI only fails on what is new. A fingerprint covers the detector, the path,
the line and the masked evidence or locator, never a value, so the file is
safe to commit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dpdp_scan import __version__
from dpdp_scan.model import Finding, Inventory, fingerprint

BASELINE_VERSION = 1


class BaselineError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Baseline:
    fingerprints: frozenset[str]
    generated_at: str = ""
    source: str = ""

    def contains(self, f: Finding) -> bool:
        return fingerprint(f) in self.fingerprints


def write_baseline(path: Path, inventory: Inventory) -> int:
    fps = sorted({fingerprint(f) for f in inventory.findings})
    doc = {
        "version": BASELINE_VERSION,
        "tool": "dpdp-scan",
        "tool_version": __version__,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "Fingerprints of accepted findings. No values are stored.",
        "fingerprints": fps,
    }
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return len(fps)


def load_baseline(path: Path) -> Baseline:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise BaselineError(f"{path}: not valid JSON") from exc
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise BaselineError(f"{path}: not a dpdp-scan baseline (version {BASELINE_VERSION})")
    fps = data.get("fingerprints")
    if not isinstance(fps, list) or not all(isinstance(x, str) for x in fps):
        raise BaselineError(f"{path}: fingerprints must be a list of strings")
    return Baseline(frozenset(fps), str(data.get("generated_at", "")), str(path))


def apply_baseline(inventory: Inventory, baseline: Baseline) -> tuple[Inventory, int]:
    """Return (findings not in the baseline, how many were suppressed)."""
    kept = Inventory()
    suppressed = 0
    for f in inventory.findings:
        if baseline.contains(f):
            suppressed += 1
        else:
            kept.add(f)
    return kept, suppressed
