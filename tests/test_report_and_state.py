from __future__ import annotations

from datetime import timedelta

import pytest

from keyleak import state
from keyleak.errors import NothingToReport
from keyleak.investigate import Investigator
from keyleak.report import build_html, support_message, write_report

from conftest import ATTACKER_IP, LEAKED, NEW_KEY, NEW_USER, NOW, REGIONS, StubFactory, load_attacker_scenario


def _investigation_dict(factory: StubFactory) -> dict:
    load_attacker_scenario(factory)
    inv = Investigator(factory, regions=REGIONS, home_regions=["us-east-1"], sleep=lambda _s: None, now=NOW).run(LEAKED)
    inv.caller = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/responder", "UserId": "x"}
    return inv.to_dict()


SWEEP = {
    "kind": "sweep",
    "started_at": NOW.isoformat(),
    "since": (NOW - timedelta(days=3)).isoformat(),
    "regions": ["us-east-1", "ap-southeast-1"],
    "resources": [
        {"kind": "EC2 instance", "region": "ap-southeast-1", "resource_id": "i-0abc123def4567890", "created": (NOW - timedelta(days=2)).isoformat(), "concern": "high", "detail": "g5.2xlarge launched after --since"},
        {"kind": "Lambda function", "region": "us-east-1", "resource_id": "thumbnailer", "created": (NOW - timedelta(days=90)).isoformat(), "concern": "low", "detail": "untouched"},
    ],
    "errors": {},
    "notes": [],
    "counts": {"high": 1, "medium": 0, "low": 1},
}

ACTION = {
    "action": "deactivate_access_key",
    "access_key_id": LEAKED,
    "user_name": "deploy-bot",
    "previous_status": "Active",
    "new_status": "Inactive",
    "changed": True,
    "verified": True,
    "at": NOW.isoformat(),
    "aws_call": f"iam:UpdateAccessKey UserName=deploy-bot AccessKeyId={LEAKED} Status=Inactive",
}


def test_report_contains_everything(factory: StubFactory):
    inv = _investigation_dict(factory)
    html = build_html(inv, SWEEP, [ACTION], generated_at=NOW)
    assert html.startswith("<!doctype html>")
    assert "SUSPICIOUS" in html
    assert LEAKED in html and NEW_KEY in html and NEW_USER in html
    assert "RunInstances" in html and "CreateAccessKey" in html
    assert ATTACKER_IP in html
    assert "i-0abc123def4567890" in html
    assert "Message to AWS Support" in html
    assert "Billing adjustment request" in html
    assert "deactivated access key " + LEAKED in html
    assert "Attacker-created key" in html
    assert "<script" not in html


def test_report_escapes_html():
    inv = {
        "root": {"kind": "AccessKeyId", "value": LEAKED},
        "verdict": "inconclusive",
        "window_start": NOW.isoformat(),
        "window_end": NOW.isoformat(),
        "regions": [],
        "reports": [{"identity": {"kind": "AccessKeyId", "value": LEAKED}, "discovered_via": "<script>alert(1)</script>", "events": [], "flags": [], "verdict": "inconclusive"}],
        "timeline": [],
        "flags": [],
        "notes": ["<b>note</b>"],
    }
    html = build_html(inv, None, [], generated_at=NOW)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;b&gt;note&lt;/b&gt;" in html


def test_report_needs_at_least_one_run():
    with pytest.raises(NothingToReport):
        build_html(None, None, [])


def test_report_sweep_only():
    html = build_html(None, SWEEP, [], generated_at=NOW)
    assert "No investigation saved" in html
    assert "i-0abc123def4567890" in html


def test_support_message_prefills_timeline_and_actions(factory: StubFactory):
    inv = _investigation_dict(factory)
    text = support_message(inv, SWEEP, [ACTION])
    assert text.startswith("Subject: Billing adjustment request")
    assert "123456789012" in text
    assert "RunInstances in ap-southeast-1" in text
    assert ATTACKER_IP in text
    assert "EC2 instance i-0abc123def4567890" in text
    assert "deactivated access key " + LEAKED in text
    assert "[your name]" in text


def test_write_report_from_state(tmp_path, factory: StubFactory):
    inv = _investigation_dict(factory)
    state.save(state.INVESTIGATE_FILE, inv)
    state.save(state.SWEEP_FILE, SWEEP)
    state.append_action(ACTION)
    out = write_report(tmp_path / "incident.html", generated_at=NOW)
    assert out.exists()
    assert "SUSPICIOUS" in out.read_text(encoding="utf-8")


def test_state_roundtrip_and_actions(tmp_path):
    path = state.save("x.json", {"when": NOW, "ids": {"b", "a"}})
    assert path.parent.name == "keyleak-home"
    loaded = state.load("x.json")
    assert loaded == {"when": NOW.isoformat(), "ids": ["a", "b"]}
    assert state.load("missing.json") is None
    state.append_action({"action": "a"})
    state.append_action({"action": "b"})
    actions = state.load_actions()
    assert [a["action"] for a in actions] == ["a", "b"]
    assert all("at" in a for a in actions)
    (state.state_dir() / state.ACTIONS_FILE).write_text("{broken", encoding="utf-8")
    assert state.load_actions() == []
