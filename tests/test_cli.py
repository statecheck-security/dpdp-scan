import pytest

from dpdp_scan import __version__
from dpdp_scan.cli import main


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_placeholder_run_reads_nothing_and_exits_2(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = tmp_path / "fixture.txt"
    secret.write_text("999999990019")  # a published UIDAI test number, never a real one
    code = main([str(tmp_path)])
    err = capsys.readouterr().err
    assert code == 2
    assert "not built yet" in err
    assert "not legal advice" in err
    # No value from the scanned tree may ever reach an output stream.
    assert "999999990019" not in err
