"""Walk a tree and run the detectors over every scannable file."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field

from dpdp_scan.detectors import DETECTORS, scan_text
from dpdp_scan.detectors.base import Detector, Step
from dpdp_scan.model import Inventory
from dpdp_scan.walker import WalkOptions, walk


@dataclass(slots=True)
class ScanResult:
    inventory: Inventory = field(default_factory=Inventory)
    files_scanned: int = 0
    files_unreadable: int = 0


def scan_path(
    root: str | os.PathLike[str],
    *,
    detectors: Iterable[Detector] = DETECTORS,
    walk_options: WalkOptions | None = None,
    min_step: Step = Step.LOW,
) -> ScanResult:
    result = ScanResult()
    dets = tuple(detectors)
    for wf in walk(root, walk_options):
        try:
            text = wf.abspath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result.files_unreadable += 1
            continue
        result.files_scanned += 1
        result.inventory.extend(scan_text(text, wf.relpath, dets, min_step=min_step))
    return result
