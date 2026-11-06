"""Run Semgrep over a list of files with the bundled rule pack.

Ported from Paranoid's ``backend/deps/scanner.py`` (Apache-2.0, see NOTICE),
made synchronous and trimmed to what a CLI needs:

- **Degrade if missing.** No Semgrep on PATH (and no ``DPDP_SCAN_SEMGREP``)
  means the rule pack is skipped and the scan reports that, rather than
  failing. The value detectors and schema classifier still run.
- **Two timeouts.** Semgrep's own ``--timeout`` bounds each file; a larger
  budget bounds the whole run, after which the process *tree* is killed
  (Semgrep spawns ``semgrep-core``; killing only the child orphans it).
- **Argv batching.** Targets are passed explicitly so Semgrep sees exactly the
  files the walker chose. Windows caps a command line at 32k characters, so
  targets are split into batches by total length.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

RULES_DIR = Path(str(files("dpdp_scan") / "rules"))

PER_FILE_TIMEOUT_S = 30
RUN_TIMEOUT_S = 300.0
#: Windows' limit is 32,767 characters; leave room for the binary, flags and config.
MAX_TARGET_ARGV_CHARS = 28_000

#: Extensions the rule pack has rules for.
RULE_LANG_SUFFIXES: frozenset[str] = frozenset(
    {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
)

Status = Literal["ok", "missing", "timeout", "error", "skipped"]


@dataclass(slots=True)
class SemgrepRun:
    status: Status
    results: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    version: str = ""
    targets: int = 0


def resolve_binary() -> str | None:
    explicit = os.environ.get("DPDP_SCAN_SEMGREP", "").strip()
    if explicit:
        return explicit
    return shutil.which("semgrep")


def base_args(binary: str, rules: Path = RULES_DIR) -> list[str]:
    return [
        binary,
        "scan",
        "--config",
        str(rules),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",  # the walker already applied .gitignore
        "--timeout",
        str(PER_FILE_TIMEOUT_S),
        "--quiet",
    ]


def batch_by_argv_length(paths: list[str], budget: int = MAX_TARGET_ARGV_CHARS) -> list[list[str]]:
    batches: list[list[str]] = []
    current: list[str] = []
    current_len = 0
    for p in paths:
        p_len = len(p) + 1
        if current and current_len + p_len > budget:
            batches.append(current)
            current, current_len = [], 0
        current.append(p)
        current_len += p_len
    if current:
        batches.append(current)
    return batches


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    try:
        if sys.platform == "win32":
            subprocess.run(  # noqa: S603
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],  # noqa: S607
                capture_output=True,
                check=False,
                timeout=10,
            )
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _exec(args: list[str], cwd: Path, timeout_s: float) -> tuple[int, str, str] | None:
    """Run one Semgrep command. None means the run timed out and was killed."""
    kwargs: dict[str, Any] = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if sys.platform == "win32"
        else {"start_new_session": True}
    )
    proc = subprocess.Popen(  # noqa: S603  (argv list, resolved binary, no shell)
        args, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
    )
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        return None
    except BaseException:
        _kill_tree(proc)
        raise
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def run_semgrep(
    root: Path,
    targets: list[str],
    *,
    rules: Path = RULES_DIR,
    run_timeout_s: float = RUN_TIMEOUT_S,
    binary: str | None = None,
) -> SemgrepRun:
    """Scan ``targets`` (repo-relative POSIX paths under ``root``) with the rule pack."""
    binary = binary or resolve_binary()
    if binary is None:
        return SemgrepRun("missing")
    targets = [t for t in targets if Path(t).suffix.lower() in RULE_LANG_SUFFIXES]
    if not targets:
        return SemgrepRun("skipped", targets=0)

    run = SemgrepRun("ok", targets=len(targets))
    for batch in batch_by_argv_length(targets):
        res = _exec([*base_args(binary, rules), "--", *batch], root, run_timeout_s)
        if res is None:
            run.status = "timeout"
            run.errors.append(
                f"semgrep exceeded {run_timeout_s:.0f}s on a batch of {len(batch)} files"
            )
            return run
        code, out, err = res
        try:
            data = json.loads(out) if out.strip() else {}
        except ValueError:
            run.status = "error"
            run.errors.append(
                f"semgrep exit {code}: unparseable output; stderr: {err.strip()[:300]}"
            )
            return run
        if not isinstance(data, dict):
            run.status = "error"
            run.errors.append("semgrep returned a non-object JSON document")
            return run
        run.version = run.version or str(data.get("version", ""))
        run.results.extend(r for r in data.get("results", []) if isinstance(r, dict))
        for e in data.get("errors", []):
            if isinstance(e, dict):
                # Partial parses are warnings; anything fatal flips the status.
                level = str(e.get("level", ""))
                msg = f"{e.get('type', 'error')}: {str(e.get('message', ''))[:200]}"
                run.errors.append(msg)
                if level == "error":
                    run.status = "error"
        if code not in (0, 1) and run.status == "ok":  # 1 = findings
            run.status = "error"
            run.errors.append(f"semgrep exit {code}: {err.strip()[:300]}")
    return run
