import shutil
import subprocess
from pathlib import Path

import pytest

from dpdp_scan.walker import DEFAULT_MAX_BYTES, WalkOptions, walk

GIT = shutil.which("git")


def _write(root: Path, rel: str, content: bytes | str = "x = 1\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        p.write_text(content, encoding="utf-8", newline="\n")
    else:
        p.write_bytes(content)
    return p


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    _write(tmp_path, "src/app.py")
    _write(tmp_path, "src/b.ts")
    _write(tmp_path, "README.md", "# hi\n")
    _write(tmp_path, "node_modules/left-pad/index.js")
    _write(tmp_path, "dist/bundle.js")
    _write(tmp_path, "package-lock.json", "{}")
    _write(tmp_path, "assets/app.min.js")
    _write(tmp_path, "assets/logo.png", b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR")
    _write(tmp_path, "big.sql", "-- " + "x" * (DEFAULT_MAX_BYTES + 10))
    _write(tmp_path, "secrets/ignored.env", "AADHAAR=999999990019\n")
    _write(tmp_path, ".gitignore", "secrets/\n")
    return tmp_path


def rels(root: Path, **kw) -> list[str]:
    return [f.relpath for f in walk(root, WalkOptions(**kw))]


def test_fallback_walk_applies_builtin_skips_but_not_gitignore(tree: Path) -> None:
    got = rels(tree, use_git=False)
    assert got == [".gitignore", "README.md", "secrets/ignored.env", "src/app.py", "src/b.ts"]


def test_fallback_walk_is_sorted_and_posix(tree: Path) -> None:
    got = rels(tree, use_git=False)
    assert got == sorted(got)
    assert all("\\" not in p for p in got)


def test_size_cap_and_binary_sniff(tree: Path) -> None:
    got = rels(tree, use_git=False)
    assert "big.sql" not in got
    assert "assets/logo.png" not in got
    assert "big.sql" in rels(tree, use_git=False, max_bytes=DEFAULT_MAX_BYTES * 2)


def test_ignore_prefixes(tree: Path) -> None:
    assert "src/app.py" not in rels(tree, use_git=False, ignore_prefixes=("src/",))
    assert "src/app.py" not in rels(tree, use_git=False, ignore_prefixes=("src",))
    assert "src/b.ts" in rels(tree, use_git=False, ignore_prefixes=("src/app.py",))


def test_walk_yields_sizes_and_absolute_paths(tree: Path) -> None:
    files = list(walk(tree, WalkOptions(use_git=False)))
    readme = next(f for f in files if f.relpath == "README.md")
    assert readme.abspath == (tree / "README.md").resolve()
    assert readme.size == len("# hi\n")


def test_not_a_directory(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        list(walk(tmp_path / "missing"))


@pytest.mark.skipif(GIT is None, reason="git not installed")
def test_git_walk_honours_gitignore_and_includes_untracked(tree: Path) -> None:
    subprocess.run([GIT, "init", "-q", str(tree)], check=True)
    subprocess.run([GIT, "-C", str(tree), "add", "src/app.py"], check=True)
    # Nothing committed: tracked (src/app.py) and untracked (README.md, src/b.ts)
    # are both listed; secrets/ is ignored by .gitignore; node_modules is not in
    # .gitignore but is skipped by the built-in list anyway.
    got = rels(tree)
    assert got == [".gitignore", "README.md", "src/app.py", "src/b.ts"]
    assert "secrets/ignored.env" not in got


@pytest.mark.skipif(GIT is None, reason="git not installed")
def test_git_walk_skips_tracked_but_deleted_files(tree: Path) -> None:
    subprocess.run([GIT, "init", "-q", str(tree)], check=True)
    subprocess.run([GIT, "-C", str(tree), "add", "src/b.ts"], check=True)
    (tree / "src" / "b.ts").unlink()
    assert "src/b.ts" not in rels(tree)


def test_git_walk_falls_back_outside_a_repo(tree: Path) -> None:
    # tmp_path is not inside a git work tree (unless the temp dir is, which would
    # make this test meaningless rather than wrong).
    got = rels(tree)
    assert "src/app.py" in got
