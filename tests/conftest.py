"""Shared test plumbing. No real AWS account is ever touched.

Every boto3 client is wrapped in a botocore Stubber. `StubFactory` satisfies the
ClientFactory protocol that keyleak uses, so the real code paths run end to end
against canned responses. The attacker scenario below is the one the README talks
about: leaked key -> CreateUser -> CreateAccessKey -> RunInstances in an unused
region.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import pytest
from botocore.stub import ANY, Stubber

UTC = timezone.utc
NOW = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)

LEAKED = "AKIAIOSFODNN7EXAMPLE"
NEW_KEY = "AKIAATTACKER00000001"
NEW_USER = "backup-svc"
OWNER = "deploy-bot"
ATTACKER_IP = "203.0.113.5"
OWNER_IP = "198.51.100.10"
ATTACKER_UA = "aws-cli/2.15.30 Python/3.11.6 Linux/6.1.0-kali7-amd64 prompt/off command/iam.create-user"
OWNER_UA = "aws-cli/2.13.0 Python/3.11.4 Darwin/22.5.0 prompt/off command/s3.ls"
ACCOUNT = "123456789012"
REGIONS = ["us-east-1", "ap-southeast-1"]

T0 = NOW - timedelta(days=3)


class StubFactory:
    """Hands out stubbed boto3 clients keyed by (service, region)."""

    def __init__(self, credential_key: str = "AKIARESPONDER0000001") -> None:
        self._clients: dict[tuple[str, str | None], Any] = {}
        self._stubbers: dict[tuple[str, str | None], Stubber] = {}
        self._credential_key = credential_key

    def _get(self, service: str, region_name: str | None) -> tuple[Any, Stubber]:
        key = (service, region_name)
        if key not in self._clients:
            client = boto3.client(
                service,
                region_name=region_name or "us-east-1",
                aws_access_key_id="testing",
                aws_secret_access_key="testing",
            )
            stubber = Stubber(client)
            stubber.activate()
            self._clients[key] = client
            self._stubbers[key] = stubber
        return self._clients[key], self._stubbers[key]

    # ClientFactory protocol
    def client(self, service: str, region_name: str | None = None) -> Any:
        return self._get(service, region_name)[0]

    def default_region(self) -> str:
        return "us-east-1"

    def credential_access_key(self) -> str | None:
        return self._credential_key

    # test helpers
    def stub(self, service: str, region_name: str | None = None) -> Stubber:
        return self._get(service, region_name)[1]

    def assert_done(self) -> None:
        for stubber in self._stubbers.values():
            stubber.assert_no_pending_responses()


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("KEYLEAK_HOME", str(tmp_path / "keyleak-home"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def factory() -> StubFactory:
    f = StubFactory()
    yield f
    f.assert_done()


# -- builders ------------------------------------------------------------------------


def ct_event(
    event_id: str,
    name: str,
    when: datetime,
    *,
    source: str = "iam.amazonaws.com",
    region: str = "us-east-1",
    ip: str = ATTACKER_IP,
    ua: str = ATTACKER_UA,
    key: str = LEAKED,
    user: str = OWNER,
    request: dict | None = None,
    response: dict | None = None,
    error: str | None = None,
    read_only: bool = False,
    resources: list[dict] | None = None,
) -> dict:
    """One item of a LookupEvents `Events` list, with a realistic CloudTrailEvent body."""
    detail: dict[str, Any] = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLEPRINCIPAL",
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
            "accountId": ACCOUNT,
            "accessKeyId": key,
            "userName": user,
        },
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": request,
        "responseElements": response,
        "eventID": event_id,
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }
    if error:
        detail["errorCode"] = error
        detail["errorMessage"] = f"{error}: simulated"
    return {
        "EventId": event_id,
        "EventName": name,
        "ReadOnly": "true" if read_only else "false",
        "AccessKeyId": key,
        "EventTime": when,
        "EventSource": source,
        "Username": user,
        "Resources": resources or [],
        "CloudTrailEvent": json.dumps(detail),
    }


def lookup_response(events: list[dict], next_token: str | None = None) -> dict:
    out: dict[str, Any] = {"Events": events}
    if next_token:
        out["NextToken"] = next_token
    return out


def expect_lookup(kind: str, value: str, next_token: str | None = None) -> dict:
    params: dict[str, Any] = {
        "LookupAttributes": [{"AttributeKey": kind, "AttributeValue": value}],
        "StartTime": ANY,
        "EndTime": ANY,
        "MaxResults": 50,
    }
    if next_token:
        params["NextToken"] = next_token
    return params


def key_last_used(user: str, when: datetime = NOW) -> dict:
    return {
        "UserName": user,
        "AccessKeyLastUsed": {"LastUsedDate": when, "ServiceName": "iam", "Region": "us-east-1"},
    }


def key_meta(user: str, key: str, status: str = "Active", created: datetime | None = None) -> dict:
    return {
        "UserName": user,
        "AccessKeyId": key,
        "Status": status,
        "CreateDate": created or (NOW - timedelta(days=200)),
    }


def iam_user(name: str, created: datetime) -> dict:
    return {
        "Path": "/",
        "UserName": name,
        "UserId": "AIDA" + name.upper().replace("-", "")[:17].ljust(17, "X"),
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "CreateDate": created,
    }


# -- the attacker scenario ------------------------------------------------------------

ATTACK_TIMES = {
    "whoami": T0,
    "list_users": T0 + timedelta(minutes=1),
    "create_user": T0 + timedelta(minutes=2),
    "create_key": T0 + timedelta(minutes=2, seconds=30),
    "run_instances": T0 + timedelta(minutes=9),
}


def leaked_key_events() -> list[dict]:
    """What the attacker did with the leaked key, plus one legit owner call."""
    return [
        ct_event("e-owner-1", "ListBuckets", T0 - timedelta(days=1), source="s3.amazonaws.com", ip=OWNER_IP, ua=OWNER_UA, read_only=True),
        ct_event("e-attk-1", "GetCallerIdentity", ATTACK_TIMES["whoami"], source="sts.amazonaws.com", read_only=True),
        ct_event("e-attk-2", "ListUsers", ATTACK_TIMES["list_users"], read_only=True),
        ct_event(
            "e-attk-3",
            "CreateUser",
            ATTACK_TIMES["create_user"],
            request={"userName": NEW_USER},
            response={"user": {"userName": NEW_USER, "arn": f"arn:aws:iam::{ACCOUNT}:user/{NEW_USER}", "userId": "AIDANEWUSER000000001", "createDate": "Oct 14, 2026 12:02:00 PM"}},
            resources=[{"ResourceType": "AWS::IAM::User", "ResourceName": NEW_USER}],
        ),
        ct_event(
            "e-attk-4",
            "CreateAccessKey",
            ATTACK_TIMES["create_key"],
            request={"userName": NEW_USER},
            response={"accessKey": {"accessKeyId": NEW_KEY, "status": "Active", "userName": NEW_USER, "createDate": "Oct 14, 2026 12:02:30 PM"}},
            resources=[{"ResourceType": "AWS::IAM::AccessKey", "ResourceName": NEW_KEY}],
        ),
    ]


def run_instances_event() -> dict:
    return ct_event(
        "e-attk-5",
        "RunInstances",
        ATTACK_TIMES["run_instances"],
        source="ec2.amazonaws.com",
        region="ap-southeast-1",
        key=NEW_KEY,
        user=NEW_USER,
        ua="Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 os/linux python/3.10.12 cfg/retry-mode#legacy Botocore/1.34.0",
        request={"instancesSet": {"items": [{"imageId": "ami-0abcdef1234567890", "minCount": 8, "maxCount": 8}]}, "instanceType": "g5.2xlarge"},
        response={"instancesSet": {"items": [{"instanceId": f"i-0{i:016x}"} for i in range(8)]}},
        resources=[{"ResourceType": "AWS::EC2::Instance", "ResourceName": "i-00000000000000001"}],
    )


def load_attacker_scenario(factory: StubFactory, *, regions: list[str] = REGIONS) -> None:
    """Register every stubbed response the investigation will consume, in call order.

    Breadth-first order: leaked key -> user backup-svc (CreateUser) -> key NEW_KEY
    (CreateAccessKey). The RunInstances event shows up under both the new user and
    the new key; keyleak must de-duplicate it.
    """
    iam = factory.stub("iam")
    # 1. root key: owner lookup
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, created=NOW - timedelta(days=228))]},
        {"UserName": OWNER},
    )
    # 2. new user: get_user + its keys
    iam.add_response("get_user", {"User": iam_user(NEW_USER, ATTACK_TIMES["create_user"])}, {"UserName": NEW_USER})
    iam.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": [key_meta(NEW_USER, NEW_KEY, created=ATTACK_TIMES["create_key"])]},
        {"UserName": NEW_USER},
    )
    # 3. new key: owner lookup (keys for backup-svc are cached, no second list call)
    iam.add_response("get_access_key_last_used", key_last_used(NEW_USER), {"AccessKeyId": NEW_KEY})

    for region in regions:
        ct = factory.stub("cloudtrail", region)
        root_events = leaked_key_events() if region == "us-east-1" else []
        ct.add_response("lookup_events", lookup_response(root_events), expect_lookup("AccessKeyId", LEAKED))
        user_events = [run_instances_event()] if region == "ap-southeast-1" else []
        ct.add_response("lookup_events", lookup_response(user_events), expect_lookup("Username", NEW_USER))
        key_events = [run_instances_event()] if region == "ap-southeast-1" else []
        ct.add_response("lookup_events", lookup_response(key_events), expect_lookup("AccessKeyId", NEW_KEY))


def load_caller_identity(factory: StubFactory) -> None:
    factory.stub("sts").add_response(
        "get_caller_identity",
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/responder", "UserId": "AIDARESPONDER0000001"},
        {},
    )
