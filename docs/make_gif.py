"""Render docs/assets/demo.gif for keyleak from the stubbed attacker scenario.

    pip install pillow
    python docs/make_gif.py

Runs the CLI against the same botocore stubs the tests use, so no AWS account is
touched and every value is fake. Needs tests/ on the path (run from the repo root).
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "docs"))

from click.testing import CliRunner  # noqa: E402

from keyleak import cli as cli_module  # noqa: E402
from termgif import Scene, build, cut_before  # noqa: E402

from conftest import (  # noqa: E402
    LEAKED,
    NOW,
    OWNER,
    StubFactory,
    iam_user,
    key_last_used,
    key_meta,
    load_attacker_scenario,
    load_caller_identity,
)

ENV = {"COLUMNS": "118", "FORCE_COLOR": "1", "TERM": "xterm-256color", "KEYLEAK_HOME": str(ROOT / "docs" / ".gif-home")}


def run(factory: StubFactory, args: list[str]) -> str:
    cli_module.make_factory = lambda profile, region: factory
    result = CliRunner().invoke(cli_module.cli, args, env=ENV)
    if result.exception and not isinstance(result.exception, SystemExit):
        raise result.exception
    factory.assert_done()
    # drop the progress status lines; they are a live display, not output
    return "\n".join(l for l in result.output.split("\n") if "Checking " not in l and "Starting..." not in l)


def main() -> None:
    f = StubFactory()
    load_attacker_scenario(f)
    load_caller_identity(f)
    investigate = run(f, ["investigate", LEAKED, "--regions", "us-east-1,ap-southeast-1", "--home-region", "us-east-1", "--known-ip", "198.51.100.10"])
    investigate = cut_before(investigate, "Discovery (2)")

    since = NOW - timedelta(days=3)
    f2 = StubFactory()
    f2.stub("ec2", "us-east-1").add_response("describe_instances", {"Reservations": [{"Instances": [{"InstanceId": "i-0f1e2d3c4b5a69788", "InstanceType": "t3.small", "LaunchTime": NOW - timedelta(days=210), "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": "web-prod"}]}]}]}, {"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running"]}], "MaxResults": 1000})
    f2.stub("lambda", "us-east-1").add_response("list_functions", {"Functions": []}, {})
    f2.stub("ec2", "ap-southeast-1").add_response("describe_instances", {"Reservations": [{"Instances": [{"InstanceId": f"i-0{i:016x}", "InstanceType": "g5.2xlarge", "LaunchTime": since + timedelta(minutes=9), "State": {"Name": "running"}} for i in (0x9A1, 0x9A2, 0x9A3)]}]}, {"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running"]}], "MaxResults": 1000})
    f2.stub("lambda", "ap-southeast-1").add_response("list_functions", {"Functions": []}, {})
    iam = f2.stub("iam")
    iam.add_response("list_users", {"Users": [iam_user("deploy-bot", NOW - timedelta(days=300)), iam_user("backup-svc", since + timedelta(minutes=2))], "IsTruncated": False}, {})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta("deploy-bot", LEAKED, created=NOW - timedelta(days=228))]}, {"UserName": "deploy-bot"})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta("backup-svc", "AKIAATTACKER00000001", created=since + timedelta(minutes=2, seconds=30))]}, {"UserName": "backup-svc"})
    sweep = run(f2, ["sweep", "--regions", "us-east-1,ap-southeast-1", "--since", "2026-10-14"])
    sweep = cut_before(sweep, "  - Only EC2")

    f3 = StubFactory()
    iam = f3.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, "Active")]}, {"UserName": OWNER})
    iam.add_response("update_access_key", {}, {"UserName": OWNER, "AccessKeyId": LEAKED, "Status": "Inactive"})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, "Inactive")]}, {"UserName": OWNER})
    contain = run(f3, ["contain", LEAKED, "--confirm"])

    build([
        Scene("keyleak — what did the attacker do with your key?", f"keyleak investigate {LEAKED} --home-region us-east-1", investigate, hold=22),
        Scene("keyleak — what is still running?", "keyleak sweep --since 2026-10-14", sweep, hold=18),
        Scene("keyleak — the one change it makes, and only with --confirm", f"keyleak contain {LEAKED} --confirm", contain, hold=20),
    ], ROOT / "docs" / "assets" / "demo.gif", cols=118)


if __name__ == "__main__":
    main()
