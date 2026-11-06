from pathlib import Path

import pytest

from dpdp_scan import __version__
from dpdp_scan.cli import main
from dpdp_scan.detectors.checksums import verhoeff_check_digit

AADHAAR = "45678901234" + verhoeff_check_digit("45678901234")


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
