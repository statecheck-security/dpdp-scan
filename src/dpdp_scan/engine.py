"""Walk a tree and run the detectors, the schema classifier and the rule pack."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from dpdp_scan.config import Config
from dpdp_scan.detectors import DETECTORS, scan_text
from dpdp_scan.detectors.base import Detector, Step
from dpdp_scan.model import Confidence, Inventory
from dpdp_scan.schema import classify_file
from dpdp_scan.semgrep_findings import to_findings
from dpdp_scan.semgrep_runner import SemgrepRun, run_semgrep
from dpdp_scan.walker import WalkOptions, walk

STEP_FOR = {Confidence.LOW: Step.LOW, Confidence.MEDIUM: Step.MEDIUM, Confidence.HIGH: Step.HIGH}


@dataclass(slots=True)
class ScanResult:
    inventory: Inventory = field(default_factory=Inventory)
    files_scanned: int = 0
    files_unreadable: int = 0
    #: None when the rule pack was not asked for.
    semgrep: SemgrepRun | None = None
    #: Findings dropped because a baseline accepted them (set by the CLI).
    suppressed: int = 0


def scan_path(
    root: str | os.PathLike[str],
    *,
    detectors: Iterable[Detector] = DETECTORS,
    walk_options: WalkOptions | None = None,
    min_step: Step = Step.LOW,
    schemas: bool = True,
    rules: bool = True,
    config: Config | None = None,
) -> ScanResult:
    config = config or Config()
    result = ScanResult()
    dets = tuple(d for d in detectors if config.detector_enabled(d.id))
    opts = walk_options or WalkOptions()
    if config.ignore_paths:
        opts = WalkOptions(
            max_bytes=opts.max_bytes,
            ignore_prefixes=(*opts.ignore_prefixes, *config.ignore_paths),
            use_git=opts.use_git,
            skip_dirs=opts.skip_dirs,
            skip_files=opts.skip_files,
        )
    schemas = schemas and "schema" not in config.disabled
    rules = rules and "rules" not in config.disabled

    root_path = Path(root).resolve()
    targets: list[str] = []
    for wf in walk(root_path, opts):
        try:
            text = wf.abspath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result.files_unreadable += 1
            continue
        result.files_scanned += 1
        targets.append(wf.relpath)
        result.inventory.extend(
            scan_text(text, wf.relpath, dets, min_step=min_step, allow=config.allow)
        )
        if schemas:
            result.inventory.extend(
                f
                for f in classify_file(text, wf.relpath, min_step=min_step)
                if config.detector_enabled(f.detector_id)
            )
    if rules:
        result.semgrep = run_semgrep(root_path, targets)
        result.inventory.extend(
            f
            for f in to_findings(result.semgrep.results, root_path.as_posix())
            if STEP_FOR[f.confidence] >= min_step and config.detector_enabled(f.detector_id)
        )
    return result
