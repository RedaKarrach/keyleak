from __future__ import annotations

from datetime import timedelta

import pytest
from botocore.stub import ANY

from keyleak.errors import PermissionDenied
from keyleak.sweep import Sweeper, instance_concern, parse_lambda_time

from conftest import NOW, StubFactory, iam_user, key_meta

SINCE = NOW - timedelta(days=3)
EC2_PARAMS = {"Filters": [{"Name": "instance-state-name", "Values": ["pending", "running"]}], "MaxResults": 1000}


def _instance(instance_id: str, itype: str, launched, name: str | None = None) -> dict:
    inst = {"InstanceId": instance_id, "InstanceType": itype, "LaunchTime": launched, "State": {"Name": "running"}}
    if name:
        inst["Tags"] = [{"Key": "Name", "Value": name}]
    return inst


def _function(name: str, modified) -> dict:
    return {
        "FunctionName": name,
        "FunctionArn": f"arn:aws:lambda:us-east-1:123456789012:function:{name}",
        "Runtime": "python3.12",
        "LastModified": modified.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
    }


def test_sweep_ranks_resources(factory: StubFactory):
    ec2 = factory.stub("ec2", "us-east-1")
    ec2.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        _instance("i-miner00000000001", "g5.2xlarge", SINCE + timedelta(hours=1)),
                        _instance("i-small00000000002", "t3.micro", SINCE + timedelta(hours=2)),
                        _instance("i-oldweb0000000003", "t3.small", NOW - timedelta(days=200), name="web-prod"),
                    ]
                }
            ]
        },
        EC2_PARAMS,
    )
    lam = factory.stub("lambda", "us-east-1")
    lam.add_response(
        "list_functions",
        {"Functions": [_function("thumbnailer", NOW - timedelta(days=100)), _function("x1", SINCE + timedelta(hours=3))]},
        {},
    )
    iam = factory.stub("iam")
    iam.add_response(
        "list_users",
        {"Users": [iam_user("deploy-bot", NOW - timedelta(days=300)), iam_user("backup-svc", SINCE + timedelta(minutes=2))], "IsTruncated": False},
        {},
    )
    iam.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": [key_meta("deploy-bot", "AKIAIOSFODNN7EXAMPLE", created=NOW - timedelta(days=300)), key_meta("deploy-bot", "AKIABACKDOOR00000001", created=SINCE + timedelta(hours=5))]},
        {"UserName": "deploy-bot"},
    )
    iam.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": [key_meta("backup-svc", "AKIAATTACKER00000001", created=SINCE + timedelta(minutes=3))]},
        {"UserName": "backup-svc"},
    )

    result = Sweeper(factory, regions=["us-east-1"], since=SINCE, sleep=lambda _s: None, now=NOW).run()

    by_id = {r.resource_id: r for r in result.resources}
    assert by_id["i-miner00000000001"].concern == "high"
    assert "mining" in by_id["i-miner00000000001"].detail
    assert by_id["i-small00000000002"].concern == "medium"
    assert by_id["i-oldweb0000000003"].concern == "low"
    assert 'Name="web-prod"' in by_id["i-oldweb0000000003"].detail
    assert by_id["thumbnailer"].concern == "low"
    assert by_id["x1"].concern == "medium"
    assert by_id["backup-svc"].kind == "IAM user" and by_id["backup-svc"].concern == "high"
    assert "deploy-bot" not in by_id  # old user itself is not listed
    assert by_id["AKIABACKDOOR00000001"].concern == "high"
    assert "EXISTING user deploy-bot" in by_id["AKIABACKDOOR00000001"].detail
    assert by_id["AKIAATTACKER00000001"].concern == "high"
    assert "AKIAIOSFODNN7EXAMPLE" not in by_id  # old key, not listed

    assert result.counts() == {"high": 4, "medium": 2, "low": 2}
    ordered = result.sorted_resources()
    assert [r.concern for r in ordered] == ["high"] * 4 + ["medium"] * 2 + ["low"] * 2
    assert result.errors == {}
    data = result.to_dict()
    assert data["kind"] == "sweep" and data["counts"]["high"] == 4


def test_sweep_records_denied_calls_and_continues(factory: StubFactory):
    factory.stub("ec2", "us-east-1").add_client_error(
        "describe_instances", "UnauthorizedOperation", "You are not authorized", 403, expected_params=EC2_PARAMS
    )
    factory.stub("lambda", "us-east-1").add_response("list_functions", {"Functions": []}, {})
    factory.stub("iam").add_response("list_users", {"Users": [], "IsTruncated": False}, {})
    result = Sweeper(factory, regions=["us-east-1"], since=SINCE, sleep=lambda _s: None, now=NOW).run()
    assert result.resources == []
    assert list(result.errors) == ["ec2:us-east-1"]
    assert any("denied" in n for n in result.notes)


def test_sweep_everything_denied_raises(factory: StubFactory):
    factory.stub("ec2", "us-east-1").add_client_error("describe_instances", "UnauthorizedOperation", "no", 403, expected_params=EC2_PARAMS)
    factory.stub("lambda", "us-east-1").add_client_error("list_functions", "AccessDeniedException", "no", 403, expected_params={})
    factory.stub("iam").add_client_error("list_users", "AccessDenied", "no", 403, expected_params={})
    with pytest.raises(PermissionDenied):
        Sweeper(factory, regions=["us-east-1"], since=SINCE, sleep=lambda _s: None, now=NOW).run()


def test_sweep_paginates_ec2_and_iam(factory: StubFactory):
    ec2 = factory.stub("ec2", "us-east-1")
    ec2.add_response("describe_instances", {"Reservations": [{"Instances": [_instance("i-a0000000000000001", "t3.micro", SINCE + timedelta(hours=1))]}], "NextToken": "n2"}, EC2_PARAMS)
    ec2.add_response("describe_instances", {"Reservations": [{"Instances": [_instance("i-b0000000000000002", "t3.micro", SINCE + timedelta(hours=1))]}]}, {**EC2_PARAMS, "NextToken": "n2"})
    lam = factory.stub("lambda", "us-east-1")
    lam.add_response("list_functions", {"Functions": [], "NextMarker": "m2"}, {})
    lam.add_response("list_functions", {"Functions": []}, {"Marker": "m2"})
    iam = factory.stub("iam")
    iam.add_response("list_users", {"Users": [iam_user("u1", NOW - timedelta(days=9))], "IsTruncated": True, "Marker": "um2"}, {})
    iam.add_response("list_users", {"Users": [], "IsTruncated": False}, {"Marker": "um2"})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [], "IsTruncated": True, "Marker": "k2"}, {"UserName": "u1"})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": []}, {"UserName": "u1", "Marker": "k2"})
    result = Sweeper(factory, regions=["us-east-1"], since=SINCE, sleep=lambda _s: None, now=NOW).run()
    assert sorted(r.resource_id for r in result.resources) == ["i-a0000000000000001", "i-b0000000000000002"]


@pytest.mark.parametrize(
    "itype,new,expected",
    [
        ("g5.2xlarge", True, "high"),
        ("p3.16xlarge", True, "high"),
        ("c6i.32xlarge", True, "high"),
        ("t3.micro", True, "medium"),
        ("g4dn.xlarge", False, "low"),
        ("t2.nano", False, "low"),
        ("m5.large", True, "medium"),
    ],
)
def test_instance_concern(itype, new, expected):
    launched = SINCE + timedelta(hours=1) if new else SINCE - timedelta(days=30)
    assert instance_concern(launched, itype, SINCE)[0] == expected


def test_parse_lambda_time():
    assert parse_lambda_time("2026-10-01T12:00:00.000+0000").year == 2026
    assert parse_lambda_time("2026-10-01T12:00:00Z").tzinfo is not None
    assert parse_lambda_time("garbage") is None
    assert parse_lambda_time(None) is None
