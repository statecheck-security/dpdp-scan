import shutil
import subprocess
from pathlib import Path

import pytest

from dpdp_scan import __version__
from dpdp_scan.cli import main
from dpdp_scan.detectors.checksums import verhoeff_check_digit

AADHAAR = "45678901234" + verhoeff_check_digit("45678901234")
GIT = shutil.which("git")


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_scan_prints_masked_summary_and_never_the_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "fixture.txt").write_text(f"aadhaar: {AADHAAR}\n", encoding="utf-8")
    code = main([str(tmp_path), "--no-git"])
    out = capsys.readouterr().out
    assert code == 0
    assert "1 files scanned, 1 findings" in out
    assert "in_aadhaar" in out and "S.8(5)" in out
    assert "not legal advice" in out
    assert AADHAAR not in out
    assert AADHAAR[-4:] in out  # the mask keeps the last four


def test_min_confidence_filter(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "f.txt").write_text("9812345670\n", encoding="utf-8")
    main([str(tmp_path), "--no-git", "--min-confidence", "medium"])
    assert "0 findings" in capsys.readouterr().out


def test_missing_path_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path / "nope")]) == 2
    assert "not a directory" in capsys.readouterr().err


@pytest.fixture
def two_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "leak.txt").write_text(f"aadhaar: {AADHAAR}\n", encoding="utf-8")
    (tmp_path / "clean.txt").write_text("nothing here\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_files_scans_only_the_named_files(
    two_files: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--files", "clean.txt", "--fail-on", "medium", "--no-rules"]) == 0
    assert "1 files scanned, 0 findings" in capsys.readouterr().out
    # Options after the file names parse too: pre-commit appends files after args.
    assert main(["--files", "--no-rules", "clean.txt", "leak.txt", "--fail-on", "medium"]) == 1
    out = capsys.readouterr().out
    assert "2 files scanned, 1 findings" in out and AADHAAR not in out


def test_files_with_no_files_scans_nothing(
    two_files: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--files", "--fail-on", "low", "--no-rules"]) == 0
    assert "0 files scanned" in capsys.readouterr().out


def test_files_reads_config_from_the_current_directory(
    two_files: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (two_files / ".dpdp-scan.yml").write_text("fail_on: medium\n", encoding="utf-8")
    assert main(["--files", "leak.txt", "--no-rules"]) == 1


def test_files_outside_the_current_directory_exits_2(
    two_files: Path, tmp_path_factory, capsys: pytest.CaptureFixture[str]
) -> None:
    other = tmp_path_factory.mktemp("other") / "x.txt"
    other.write_text("x\n", encoding="utf-8")
    assert main(["--files", str(other)]) == 2
    assert "outside the current directory" in capsys.readouterr().err


def test_several_paths_without_files_exits_2(
    two_files: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["leak.txt", "clean.txt"]) == 2
    assert "--files" in capsys.readouterr().err


def test_partial_scans_refuse_to_write_a_baseline(
    two_files: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--files", "leak.txt", "--write-baseline", "b.json"]) == 2
    assert main(["--staged", "--write-baseline", "b.json"]) == 2
    assert not (two_files / "b.json").exists()


def test_files_and_staged_are_exclusive(two_files: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--files", "--staged", "leak.txt"])
    assert exc.value.code == 2


@pytest.mark.skipif(GIT is None, reason="git not installed")
def test_staged_scans_only_the_index(two_files: Path, capsys: pytest.CaptureFixture[str]) -> None:
    subprocess.run([GIT, "init", "-q", "."], check=True)
    subprocess.run([GIT, "add", "clean.txt"], check=True)
    assert main(["--staged", "--fail-on", "medium", "--no-rules"]) == 0
    assert "1 files scanned, 0 findings" in capsys.readouterr().out
    subprocess.run([GIT, "add", "leak.txt"], check=True)
    assert main(["--staged", "--fail-on", "medium", "--no-rules"]) == 1


def test_staged_outside_git_exits_2(two_files: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--staged"]) == 2
    assert "not in a git work tree" in capsys.readouterr().err
