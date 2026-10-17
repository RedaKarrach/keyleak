from __future__ import annotations

from datetime import timedelta

import pytest
from botocore.stub import ANY

from keyleak.errors import CredentialsProblem, InvalidKeyId, PermissionDenied, RefusedLeakedKey
from keyleak.investigate import KIND_KEY, KIND_USER, Event, Identity, Investigator
from keyleak.rules import CATEGORY_CRYPTOMINING, CATEGORY_DISCOVERY, CATEGORY_PERSISTENCE

from conftest import (
    ATTACKER_IP,
    ATTACK_TIMES,
    LEAKED,
    NEW_KEY,
    NEW_USER,
    NOW,
    OWNER,
    OWNER_IP,
    REGIONS,
    StubFactory,
    ct_event,
    expect_lookup,
    key_last_used,
    key_meta,
    load_attacker_scenario,
    lookup_response,
)


def make_investigator(factory: StubFactory, **kwargs) -> Investigator:
    defaults = dict(regions=REGIONS, home_regions=["us-east-1"], sleep=lambda _s: None, now=NOW)
    defaults.update(kwargs)
    return Investigator(factory, **defaults)


# -- the headline test: attacker fixture, flags, and the pivot ------------------------


def test_attacker_scenario_is_flagged_and_pivoted(factory: StubFactory):
    load_attacker_scenario(factory)
    inv = make_investigator(factory).run(LEAKED)

    assert inv.verdict == "suspicious"

    root = inv.root_report
    assert root.identity == Identity(KIND_KEY, LEAKED)
    assert root.user_name == OWNER
    assert root.key_status == "Active"
    assert [e.name for e in root.events] == ["ListBuckets", "GetCallerIdentity", "ListUsers", "CreateUser", "CreateAccessKey"]

    persistence = {f.event_name for f in root.flags if f.category == CATEGORY_PERSISTENCE}
    assert persistence == {"CreateUser", "CreateAccessKey"}
    discovery = {f.event_name for f in root.flags if f.category == CATEGORY_DISCOVERY}
    assert discovery == {"GetCallerIdentity", "ListUsers", "ListBuckets"}

    # The pivot: both the new user and the new key were investigated.
    identities = [r.identity for r in inv.reports]
    assert Identity(KIND_USER, NEW_USER) in identities
    assert Identity(KIND_KEY, NEW_KEY) in identities
    assert len(inv.reports) == 3
    assert set(root.pivots) == {Identity(KIND_USER, NEW_USER), Identity(KIND_KEY, NEW_KEY)}

    new_key_report = next(r for r in inv.reports if r.identity.value == NEW_KEY)
    assert new_key_report.depth == 1
    assert "CreateAccessKey" in new_key_report.discovered_via
    assert new_key_report.user_name == NEW_USER
    mining = [f for f in new_key_report.flags if f.category == CATEGORY_CRYPTOMINING]
    assert len(mining) == 1
    assert mining[0].severity == "high"
    assert mining[0].region == "ap-southeast-1"
    assert "does not normally use" in mining[0].reason

    new_user_report = next(r for r in inv.reports if r.identity.value == NEW_USER)
    assert new_user_report.user_created == ATTACK_TIMES["create_user"]
    assert [k.access_key_id for k in new_user_report.iam_keys] == [NEW_KEY]

    # RunInstances appears under both the new user and the new key: counted once.
    assert sum(1 for f in inv.all_flags if f.event_name == "RunInstances") == 1
    assert sum(1 for e in inv.all_events if e.event_id == "e-attk-5") == 1
    assert len(inv.all_events) == 6
    assert inv.all_events[0].name == "ListBuckets"  # chronological
    assert inv.all_events[-1].name == "RunInstances"

    assert inv.suspect_ips == sorted([ATTACKER_IP, OWNER_IP])  # owner's ListBuckets is a low discovery flag
    assert inv.source_ips[ATTACKER_IP] == 5
    assert inv.regions_with_activity == ["ap-southeast-1", "us-east-1"]
    assert inv.first_flag_time == ATTACK_TIMES["whoami"] - timedelta(days=1)
    assert any("90 days" in n for n in inv.notes)

    data = inv.to_dict()
    assert data["verdict"] == "suspicious"
    assert len(data["reports"]) == 3
    assert data["flags"][0]["category"] == CATEGORY_PERSISTENCE


def test_known_ips_quiet_owner_discovery(factory: StubFactory):
    load_attacker_scenario(factory)
    inv = make_investigator(factory, known_ips=[OWNER_IP]).run(LEAKED)
    discovery_ips = {f.source_ip for f in inv.all_flags if f.category == CATEGORY_DISCOVERY}
    assert discovery_ips == {ATTACKER_IP}
    assert inv.suspect_ips == [ATTACKER_IP]


def test_run_instances_in_home_region_is_medium(factory: StubFactory):
    load_attacker_scenario(factory)
    inv = make_investigator(factory, home_regions=["ap-southeast-1"]).run(LEAKED)
    mining = [f for f in inv.all_flags if f.category == CATEGORY_CRYPTOMINING]
    assert mining[0].severity == "medium"
    assert inv.verdict == "suspicious"


# -- pivot controls ---------------------------------------------------------------------


def _root_only_stubs(factory: StubFactory, events: list[dict], *, regions=("us-east-1",)) -> None:
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED)]}, {"UserName": OWNER})
    for region in regions:
        factory.stub("cloudtrail", region).add_response(
            "lookup_events", lookup_response(events if region == "us-east-1" else []), expect_lookup("AccessKeyId", LEAKED)
        )


def _create_key_event(event_id: str, new_key: str, by_key: str, when) -> dict:
    return ct_event(
        event_id,
        "CreateAccessKey",
        when,
        key=by_key,
        request={"userName": OWNER},
        response={"accessKey": {"accessKeyId": new_key, "status": "Active", "userName": OWNER}},
    )


def test_depth_limit_records_skipped_pivots(factory: StubFactory):
    _root_only_stubs(factory, [_create_key_event("e1", NEW_KEY, LEAKED, NOW - timedelta(hours=1))])
    inv = make_investigator(factory, regions=["us-east-1"], max_depth=0).run(LEAKED)
    assert len(inv.reports) == 1
    assert inv.root_report.pivots == [Identity(KIND_KEY, NEW_KEY)]
    assert len(inv.skipped_pivots) == 1
    assert "depth limit" in inv.skipped_pivots[0]["reason"]
    assert inv.verdict == "suspicious"


def test_no_pivot_flag(factory: StubFactory):
    _root_only_stubs(factory, [_create_key_event("e1", NEW_KEY, LEAKED, NOW - timedelta(hours=1))])
    inv = make_investigator(factory, regions=["us-east-1"], pivot=False).run(LEAKED)
    assert len(inv.reports) == 1
    assert "disabled" in inv.skipped_pivots[0]["reason"]


def test_pivot_loop_is_cut_by_visited_set(factory: StubFactory):
    """Key A created key B, and B's history shows it creating A. Two reports, no loop."""
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED), key_meta(OWNER, NEW_KEY)]}, {"UserName": OWNER})
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": NEW_KEY})
    ct = factory.stub("cloudtrail", "us-east-1")
    ct.add_response(
        "lookup_events",
        lookup_response([_create_key_event("e1", NEW_KEY, LEAKED, NOW - timedelta(hours=2))]),
        expect_lookup("AccessKeyId", LEAKED),
    )
    ct.add_response(
        "lookup_events",
        lookup_response([_create_key_event("e2", LEAKED, NEW_KEY, NOW - timedelta(hours=1))]),
        expect_lookup("AccessKeyId", NEW_KEY),
    )
    inv = make_investigator(factory, regions=["us-east-1"], max_depth=5).run(LEAKED)
    assert [r.identity.value for r in inv.reports] == [LEAKED, NEW_KEY]
    assert not inv.skipped_pivots


def test_failed_create_user_does_not_pivot(factory: StubFactory):
    denied = ct_event("e1", "CreateUser", NOW - timedelta(hours=1), request={"userName": "ghost"}, error="AccessDenied")
    _root_only_stubs(factory, [denied])
    inv = make_investigator(factory, regions=["us-east-1"]).run(LEAKED)
    assert len(inv.reports) == 1
    assert inv.root_report.pivots == []
    flag = inv.root_report.flags[0]
    assert flag.failed is True
    assert "call failed: AccessDenied" in flag.reason
    assert inv.verdict == "suspicious"  # a failed attempt is still an attacker


def test_assume_role_pivots_to_temporary_key(factory: StubFactory):
    temp = "ASIATEMPORARY0000001"
    assume = ct_event(
        "e1",
        "AssumeRole",
        NOW - timedelta(hours=1),
        source="sts.amazonaws.com",
        request={"roleArn": "arn:aws:iam::123456789012:role/Admin", "roleSessionName": "x"},
        response={"credentials": {"accessKeyId": temp, "sessionToken": "REDACTED", "expiration": "Oct 17, 2026 1:00:00 PM"}},
    )
    _root_only_stubs(factory, [assume])
    iam = factory.stub("iam")
    iam.add_client_error("get_access_key_last_used", "NoSuchEntity", "not found", 404, expected_params={"AccessKeyId": temp})
    factory.stub("cloudtrail", "us-east-1").add_response(
        "lookup_events",
        lookup_response([ct_event("e2", "ListBuckets", NOW - timedelta(minutes=50), source="s3.amazonaws.com", key=temp, read_only=True)]),
        expect_lookup("AccessKeyId", temp),
    )
    inv = make_investigator(factory, regions=["us-east-1"]).run(LEAKED)
    assert [r.identity.value for r in inv.reports] == [LEAKED, temp]
    assert "IAM has no record" in inv.reports[1].iam_note
    assert inv.reports[1].events[0].name == "ListBuckets"


# -- robustness ----------------------------------------------------------------------


def test_throttling_is_retried_with_backoff(factory: StubFactory):
    sleeps: list[float] = []
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED)]}, {"UserName": OWNER})
    ct = factory.stub("cloudtrail", "us-east-1")
    ct.add_client_error("lookup_events", "ThrottlingException", "Rate exceeded", 400, expected_params=expect_lookup("AccessKeyId", LEAKED))
    ct.add_client_error("lookup_events", "ThrottlingException", "Rate exceeded", 400, expected_params=expect_lookup("AccessKeyId", LEAKED))
    ct.add_response("lookup_events", lookup_response([]), expect_lookup("AccessKeyId", LEAKED))
    inv = make_investigator(factory, regions=["us-east-1"], sleep=sleeps.append).run(LEAKED)
    assert len(sleeps) == 2
    assert sleeps[1] > sleeps[0]
    assert inv.root_report.region_errors == {}
    assert inv.verdict == "inconclusive"


def test_pagination_follows_next_token(factory: StubFactory):
    sleeps: list[float] = []
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED)]}, {"UserName": OWNER})
    ct = factory.stub("cloudtrail", "us-east-1")
    first = ct_event("p1", "ListBuckets", NOW - timedelta(hours=2), source="s3.amazonaws.com", ip=OWNER_IP, read_only=True)
    second = ct_event("p2", "GetUser", NOW - timedelta(hours=1), ip=OWNER_IP, read_only=True)
    ct.add_response("lookup_events", lookup_response([first], next_token="page2"), expect_lookup("AccessKeyId", LEAKED))
    ct.add_response("lookup_events", lookup_response([second]), expect_lookup("AccessKeyId", LEAKED, next_token="page2"))
    inv = make_investigator(factory, regions=["us-east-1"], known_ips=[OWNER_IP], sleep=sleeps.append, page_pause=0.25).run(LEAKED)
    assert [e.name for e in inv.root_report.events] == ["ListBuckets", "GetUser"]
    assert sleeps == [0.25]
    assert inv.verdict == "likely clean"


def test_access_denied_everywhere_is_a_clear_error(factory: StubFactory):
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED)]}, {"UserName": OWNER})
    for region in REGIONS:
        factory.stub("cloudtrail", region).add_client_error(
            "lookup_events", "AccessDeniedException", "not authorized", 403, expected_params=expect_lookup("AccessKeyId", LEAKED)
        )
    with pytest.raises(PermissionDenied) as info:
        make_investigator(factory).run(LEAKED)
    assert "keyleak-readonly-policy.json" in str(info.value)


def test_one_region_denied_is_recorded_and_the_rest_continue(factory: StubFactory):
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED)]}, {"UserName": OWNER})
    factory.stub("cloudtrail", "us-east-1").add_response(
        "lookup_events",
        lookup_response([ct_event("e1", "GetUser", NOW - timedelta(hours=1), ip=OWNER_IP, read_only=True)]),
        expect_lookup("AccessKeyId", LEAKED),
    )
    factory.stub("cloudtrail", "ap-southeast-1").add_client_error(
        "lookup_events", "AccessDeniedException", "not authorized", 403, expected_params=expect_lookup("AccessKeyId", LEAKED)
    )
    inv = make_investigator(factory).run(LEAKED)
    assert list(inv.root_report.region_errors) == ["ap-southeast-1"]
    assert inv.root_report.region_errors["ap-southeast-1"].startswith("AccessDeniedException")
    assert len(inv.root_report.events) == 1
    assert inv.verdict == "inconclusive"  # errors mean we cannot call it clean


def test_missing_iam_permission_still_produces_a_timeline(factory: StubFactory):
    factory.stub("iam").add_client_error(
        "get_access_key_last_used", "AccessDenied", "not authorized", 403, expected_params={"AccessKeyId": LEAKED}
    )
    factory.stub("cloudtrail", "us-east-1").add_response(
        "lookup_events",
        lookup_response([ct_event("e1", "CreateUser", NOW - timedelta(hours=1), request={"userName": "x"}, response={"user": {"userName": "x"}})]),
        expect_lookup("AccessKeyId", LEAKED),
    )
    # pivot to user x: get_user denied too, lookup empty
    factory.stub("iam").add_client_error("get_user", "AccessDenied", "not authorized", 403, expected_params={"UserName": "x"})
    factory.stub("cloudtrail", "us-east-1").add_response("lookup_events", lookup_response([]), expect_lookup("Username", "x"))
    inv = make_investigator(factory, regions=["us-east-1"]).run(LEAKED)
    assert inv.root_report.user_name is None
    assert "No IAM read permission" in inv.root_report.iam_note
    assert inv.verdict == "suspicious"
    assert len(inv.reports) == 2


def test_expired_credentials_fail_fast(factory: StubFactory):
    factory.stub("iam").add_client_error(
        "get_access_key_last_used", "ExpiredToken", "The security token included in the request is expired", 403,
        expected_params={"AccessKeyId": LEAKED},
    )
    with pytest.raises(CredentialsProblem) as info:
        make_investigator(factory, regions=["us-east-1"]).run(LEAKED)
    assert "expired" in str(info.value).lower()


def test_invalid_key_format_is_rejected_before_any_aws_call(factory: StubFactory):
    with pytest.raises(InvalidKeyId) as info:
        make_investigator(factory).run("AKIA-not-a-real-key")
    assert "does not look like an AWS access key ID" in str(info.value)
    with pytest.raises(InvalidKeyId):
        make_investigator(factory).run("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")  # a secret, not an ID


def test_refuses_to_run_as_the_leaked_key():
    factory = StubFactory(credential_key=LEAKED)
    with pytest.raises(RefusedLeakedKey) as info:
        make_investigator(factory).run(LEAKED)
    assert "DIFFERENT identity" in str(info.value)
    factory.assert_done()


def test_event_from_lookup_survives_bad_json():
    raw = {"EventId": "x", "EventName": "ListBuckets", "EventTime": NOW, "EventSource": "s3.amazonaws.com", "CloudTrailEvent": "{not json"}
    ev = Event.from_lookup(raw, region="eu-west-1")
    assert ev.name == "ListBuckets"
    assert ev.region == "eu-west-1"
    assert ev.source_ip == ""
    assert ev.request_parameters == {}


def test_lookback_is_capped_at_90_days(factory: StubFactory):
    inv = make_investigator(factory, lookback_days=400)
    assert inv.lookback_days == 90
