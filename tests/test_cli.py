from __future__ import annotations

import json
from datetime import timedelta

import pytest
from click.testing import CliRunner

from keyleak import cli as cli_module
from keyleak import state
from keyleak.cli import cli, main

from conftest import LEAKED, NEW_KEY, NEW_USER, NOW, OWNER, StubFactory, key_last_used, key_meta, load_attacker_scenario, load_caller_identity

REGION_ARG = "us-east-1,ap-southeast-1"


@pytest.fixture
def use_factory(monkeypatch):
    """Route the CLI to a StubFactory. Returns it so tests can load stubs."""
    created: list[StubFactory] = []

    def _make(profile, region):
        f = StubFactory()
        created.append(f)
        return f

    monkeypatch.setattr(cli_module, "make_factory", _make)

    def _prime(loader):
        # The CLI builds the factory lazily; build it now so stubs can be loaded.
        f = StubFactory()
        loader(f)
        monkeypatch.setattr(cli_module, "make_factory", lambda profile, region: f)
        created.append(f)
        return f

    yield _prime
    for f in created:
        f.assert_done()


def test_investigate_json_and_report(use_factory, tmp_path):
    def loader(f: StubFactory):
        load_attacker_scenario(f)
        load_caller_identity(f)

    use_factory(loader)
    runner = CliRunner()
    result = runner.invoke(cli, ["investigate", LEAKED, "--regions", REGION_ARG, "--home-region", "us-east-1", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["verdict"] == "suspicious"
    assert data["caller"]["Account"] == "123456789012"
    assert [r["identity"]["value"] for r in data["reports"]] == [LEAKED, NEW_USER, NEW_KEY]
    assert state.load(state.INVESTIGATE_FILE)["verdict"] == "suspicious"

    out = tmp_path / "incident.html"
    result = runner.invoke(cli, ["report", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "Wrote" in result.output
    assert "RunInstances" in out.read_text(encoding="utf-8")


def test_investigate_rich_output(use_factory):
    def loader(f: StubFactory):
        load_attacker_scenario(f)
        load_caller_identity(f)

    use_factory(loader)
    result = CliRunner().invoke(cli, ["investigate", LEAKED, "--regions", REGION_ARG, "--home-region", "us-east-1"], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    out = result.output
    assert "SUSPICIOUS" in out
    assert "Identities investigated" in out
    assert NEW_KEY in out and NEW_USER in out
    assert "Persistence" in out and "Cryptomining" in out
    assert "90 days" in out
    assert f"keyleak contain {NEW_KEY} --confirm" in out


def test_sweep_cli_uses_last_investigate_for_since(use_factory):
    state.save(state.INVESTIGATE_FILE, {"first_flag_time": (NOW - timedelta(days=2)).isoformat()})

    def loader(f: StubFactory):
        f.stub("ec2", "us-east-1").add_response("describe_instances", {"Reservations": []}, {"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running"]}], "MaxResults": 1000})
        f.stub("lambda", "us-east-1").add_response("list_functions", {"Functions": []}, {})
        f.stub("iam").add_response("list_users", {"Users": [], "IsTruncated": False}, {})

    use_factory(loader)
    result = CliRunner().invoke(cli, ["sweep", "--regions", "us-east-1", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["resources"] == []
    assert data["since"].startswith((NOW - timedelta(days=2)).strftime("%Y-%m-%d"))
    assert "first flagged event" in result.output
    assert state.load(state.SWEEP_FILE)["kind"] == "sweep"


def test_sweep_cli_explicit_since(use_factory):
    def loader(f: StubFactory):
        f.stub("ec2", "us-east-1").add_response("describe_instances", {"Reservations": []}, {"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running"]}], "MaxResults": 1000})
        f.stub("lambda", "us-east-1").add_response("list_functions", {"Functions": []}, {})
        f.stub("iam").add_response("list_users", {"Users": [], "IsTruncated": False}, {})

    use_factory(loader)
    result = CliRunner().invoke(cli, ["sweep", "--regions", "us-east-1", "--since", "2026-10-01"])
    assert result.exit_code == 0, result.output
    assert "Nothing running" in result.output


def test_contain_cli_records_action(use_factory):
    def loader(f: StubFactory):
        iam = f.stub("iam")
        iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
        iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, "Active")]}, {"UserName": OWNER})
        iam.add_response("update_access_key", {}, {"UserName": OWNER, "AccessKeyId": LEAKED, "Status": "Inactive"})
        iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, "Inactive")]}, {"UserName": OWNER})

    use_factory(loader)
    result = CliRunner().invoke(cli, ["contain", LEAKED, "--confirm"])
    assert result.exit_code == 0, result.output
    assert "Active -> Inactive" in result.output
    assert "Nothing else was touched" in result.output
    actions = state.load_actions()
    assert len(actions) == 1 and actions[0]["access_key_id"] == LEAKED


def test_contain_without_confirm_exits_2_with_message(capsys):
    with pytest.raises(SystemExit) as info:
        main(["contain", LEAKED])
    assert info.value.code == 2
    err = capsys.readouterr().err
    assert "--confirm" in err
    assert "Nothing was done" in err
    assert "Traceback" not in err


def test_invalid_key_exits_2(capsys):
    with pytest.raises(SystemExit) as info:
        main(["investigate", "nope"])
    assert info.value.code == 2
    assert "does not look like an AWS access key ID" in capsys.readouterr().err


def test_report_without_runs_exits_2(capsys, tmp_path):
    with pytest.raises(SystemExit) as info:
        main(["report", "--out", str(tmp_path / "r.html")])
    assert info.value.code == 2
    assert "Nothing to report yet" in capsys.readouterr().err


def test_unexpected_error_is_short(monkeypatch, capsys):
    def boom(profile, region):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli_module, "make_factory", boom)
    with pytest.raises(SystemExit) as info:
        main(["investigate", LEAKED])
    assert info.value.code == 3
    err = capsys.readouterr().err
    assert "kaboom" in err and "--debug" in err and "Traceback" not in err


def test_help_mentions_safety_rule():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "never authenticates with the leaked key" in result.output
