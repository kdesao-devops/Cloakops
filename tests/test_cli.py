from __future__ import annotations

import io
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cloakops.cli import EXIT_FAIL_CLOSED, EXIT_OK, EXIT_USAGE, main
from cloakops.preamble import PREAMBLE
from cloakops.store import Store, StoreError
from test_pseudo_structure import TFSTATE

LOG = (
    "ERROR AccessDenied: arn:aws:iam::123456789012:role/acme-deployer on s3://acme-tfstate "
    "from 10.42.3.17\nowner: jane.doe@acme.io\n"
)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CLOAKOPS_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def run(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
    stdin: str = "",
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> tuple[int, str, str]:
    if monkeypatch is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_mask_then_unmask_in_separate_invocations(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    code, masked, err = run(["mask", "--session", "s1"], capsys, LOG, monkeypatch)
    assert code == EXIT_OK and "acme" not in masked and "10.42.3.17" not in masked
    assert "jane" not in err and "masked" in err  # summary on stderr, without values
    code, restored, _ = run(["unmask", "--session", "s1"], capsys, masked, monkeypatch)
    assert code == EXIT_OK and restored == LOG


def test_session_files_are_private(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    run(["mask", "--session", "s1"], capsys, LOG, monkeypatch)
    assert (home.stat().st_mode & 0o777) == 0o700
    assert ((home / "sessions" / "s1.json").stat().st_mode & 0o777) == 0o600


def test_readable_session_file_is_refused(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    run(["mask", "--session", "s1"], capsys, LOG, monkeypatch)
    (home / "sessions" / "s1.json").chmod(0o644)
    code, out, err = run(["unmask", "--session", "s1"], capsys, "x", monkeypatch)
    assert code == EXIT_FAIL_CLOSED and out == "" and "chmod" in err


def test_expired_session_is_discarded(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    run(["mask", "--session", "old"], capsys, LOG, monkeypatch)
    path = home / "sessions" / "old.json"
    state = json.loads(path.read_text())
    state["created_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    path.write_text(json.dumps(state))
    path.chmod(0o600)
    store = Store(home)
    assert store.load("old").session.reverse == {}
    assert not path.exists()


def test_unmask_needs_an_existing_session(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _ = run(["unmask", "--session", "nope"], capsys, "x", monkeypatch)
    assert code == EXIT_USAGE and out == ""


def test_preamble(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, out, _ = run(["mask", "--session", "s", "--preamble"], capsys, LOG, monkeypatch)
    assert out.startswith(PREAMBLE)


def test_file_input_and_tfstate(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "terraform.tfstate"
    source.write_text(TFSTATE)
    code, out, _ = run(["mask", str(source), "--session", "tf"], capsys)
    assert code == EXIT_OK
    json.loads(out)  # still valid JSON


def test_fail_closed_writes_nothing(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Make the pipeline find a residue: a buggy generator keeps the value inside the pseudonym.
    import cloakops.pseudo.generators as generators

    monkeypatch.setitem(generators.GENERATORS, generators.E.ORGANIZATION, lambda v, c, n: f"{v} x")
    code, out, err = run(
        ["mask", "--session", "s"], capsys, "client: Jacquil Industries\n", monkeypatch
    )
    assert code == EXIT_FAIL_CLOSED and out == ""
    assert "Nothing was written" in err and "Jacquil" not in err


def test_unexpected_errors_fail_closed_without_values(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: object, text: str) -> None:
        raise KeyError(text)  # an exception whose message carries the input

    monkeypatch.setattr("cloakops.pipeline.Pipeline.mask", boom)
    monkeypatch.delenv("CLOAKOPS_DEBUG", raising=False)
    code, out, err = run(["mask", "--session", "s"], capsys, "secret-value-123\n", monkeypatch)
    assert code == EXIT_FAIL_CLOSED and out == ""
    assert "KeyError" in err and "secret-value-123" not in err


def test_scan_lists_types_and_positions_without_values(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _ = run(["scan"], capsys, LOG, monkeypatch)
    assert code == EXIT_OK
    assert "arn" in out and "ip_address" in out
    assert "10.42.3.17" not in out and "acme" not in out


def test_seed_dictionary_commands(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    run(["dict", "add", "Brindel", "Logistics"], capsys)
    run(["dict", "add", "person: Jane Martin"], capsys)
    _, listed, _ = run(["dict", "list"], capsys)
    assert listed.splitlines() == ["Brindel Logistics", "person: Jane Martin"]
    assert ((home / "seed.txt").stat().st_mode & 0o777) == 0o600
    _, out, _ = run(["mask", "--session", "s"], capsys, "Brindel called Jane Martin\n", monkeypatch)
    assert "Brindel" not in out and "Martin" not in out
    run(["dict", "remove", "person: Jane Martin"], capsys)
    _, listed, _ = run(["dict", "list"], capsys)
    assert listed.splitlines() == ["Brindel Logistics"]


def test_session_management(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    run(["mask", "--session", "a"], capsys, LOG, monkeypatch)
    _, listed, _ = run(["session", "list"], capsys)
    assert listed.startswith("a\t") and "active" in listed
    assert run(["session", "delete", "a"], capsys)[0] == EXIT_OK
    assert run(["session", "delete", "a"], capsys)[0] == EXIT_USAGE


@pytest.mark.parametrize("name", ["../etc/passwd", "a/b", "", "x" * 65])
def test_session_names_cannot_escape_the_store(home: Path, name: str) -> None:
    with pytest.raises(StoreError):
        Store(home).load(name)


def test_config_file_org_domains(
    home: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text('organization_domains = ["korvane.com"]\n')
    _, out, _ = run(
        ["mask", "--session", "s"], capsys, "see https://pay.korvane.com\n", monkeypatch
    )
    assert "korvane" not in out
    assert os.environ["CLOAKOPS_HOME"] == str(home)
