"""Which files get scanned.

Rules, in order:

1. Inside a git work tree, the file list is what ``git ls-files`` reports for
   tracked and untracked-but-not-ignored files. That gives exact ``.gitignore``
   semantics (nested ignore files, negations, global excludes) with no
   reimplementation. Outside git, or when git is missing, the walker descends
   the tree itself and applies only the built-in skips below.
2. Vendored and generated trees are always skipped, ignored or not: a committed
   ``node_modules`` is still not the repository's own code.
3. Lockfiles and minified bundles are skipped by name.
4. Files over ``max_bytes`` are skipped.
5. Binary files (a NUL byte in the first 8 KiB) are skipped.

Every yielded path is repo-relative with POSIX separators, and the sequence is
sorted, so a scan of the same tree is deterministic on every platform.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

#: Directory names never descended into or yielded, wherever they appear.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        "vendor",
        "dist",
        "build",
        "out",
        "target",
        ".next",
        ".nuxt",
        ".output",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".cache",
        "coverage",
        ".terraform",
    }
)

#: File names never scanned. Lockfiles carry hashes and URLs, not personal data,
#: and they are enormous.
SKIP_FILES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "Cargo.lock",
        "Gemfile.lock",
        "composer.lock",
        "go.sum",
        "packages.lock.json",
    }
)

#: File-name suffixes never scanned: minified bundles and source maps.
SKIP_SUFFIXES: tuple[str, ...] = (".min.js", ".min.css", ".map", ".bundle.js")

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
_SNIFF_BYTES = 8 * 1024


@dataclass(frozen=True, slots=True)
class WalkOptions:
    max_bytes: int = DEFAULT_MAX_BYTES
    #: Extra repo-relative prefixes or globs to skip (``ignore.paths`` in
    #: ``.dpdp-scan.yml``). ``fixtures/`` skips a tree; ``docs/**/*.md`` is a glob.
    ignore_prefixes: tuple[str, ...] = ()
    #: Force the fallback walk even inside a git work tree. For tests.
    use_git: bool = True
    skip_dirs: frozenset[str] = field(default=SKIP_DIRS)
    skip_files: frozenset[str] = field(default=SKIP_FILES)


@dataclass(frozen=True, slots=True)
class WalkedFile:
    relpath: str  # POSIX, relative to the root
    abspath: Path
    size: int


def _git_ls_files(root: Path) -> list[str] | None:
    """Tracked plus untracked-not-ignored files, or None when git cannot answer."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603  (argv list, fixed executable, no shell)
            [git, "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None  # not a work tree, or git refused
    return [p for p in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


def _is_skipped_path(relpath: str, opts: WalkOptions) -> bool:
    parts = PurePosixPath(relpath).parts
    if any(part in opts.skip_dirs for part in parts[:-1]):
        return True
    name = parts[-1]
    if name in opts.skip_files or name.endswith(SKIP_SUFFIXES):
        return True
    for p in opts.ignore_prefixes:
        if any(ch in p for ch in "*?["):
            # A glob. "**" matches across directories (fnmatch's "*" already does).
            if fnmatch.fnmatchcase(relpath, p.replace("**/", "*").replace("**", "*")):
                return True
        elif relpath == p or relpath.startswith(p.rstrip("/") + "/"):
            return True
    return False


def _looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(_SNIFF_BYTES)
    except OSError:
        return True  # unreadable: treat as not scannable


def _fallback_listing(root: Path, opts: WalkOptions) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in opts.skip_dirs)
        rel_dir = Path(dirpath).relative_to(root)
        for name in filenames:
            rel = (rel_dir / name).as_posix() if str(rel_dir) != "." else name
            found.append(rel)
    return found


def walk(root: str | os.PathLike[str], opts: WalkOptions | None = None) -> Iterator[WalkedFile]:
    """Yield the files under ``root`` that a scan should read, in sorted order."""
    opts = opts or WalkOptions()
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(root_path)

    listing = _git_ls_files(root_path) if opts.use_git else None
    if listing is None:
        listing = _fallback_listing(root_path, opts)

    for rel in sorted(set(listing)):
        if _is_skipped_path(rel, opts):
            continue
        abspath = root_path / rel
        if abspath.is_symlink() or not abspath.is_file():
            continue  # git lists symlinks and may list deleted-but-tracked files
        size = abspath.stat().st_size
        if size > opts.max_bytes:
            continue
        if _looks_binary(abspath):
            continue
        yield WalkedFile(relpath=rel, abspath=abspath, size=size)
