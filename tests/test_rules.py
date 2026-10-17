from __future__ import annotations

from keyleak.rules import (
    CATEGORY_CRYPTOMINING,
    CATEGORY_DISCOVERY,
    CATEGORY_EMAIL,
    CATEGORY_LLM,
    CATEGORY_PERSISTENCE,
    classify_event,
    verdict_for,
)

from conftest import NOW


def _classify(name, source, **kw):
    args = dict(
        event_id="e",
        event_name=name,
        event_source=source,
        region="us-east-1",
        time=NOW,
        source_ip="203.0.113.9",
        identity="AKIAX",
        error_code=None,
        known_ips=[],
        home_regions=["us-east-1"],
    )
    args.update(kw)
    return classify_event(**args)


def test_persistence_events():
    for name in ["CreateUser", "CreateAccessKey", "CreateLoginProfile", "AttachUserPolicy", "PutUserPolicy", "UpdateAssumeRolePolicy", "CreateRole"]:
        flags = _classify(name, "iam.amazonaws.com")
        assert [f.category for f in flags] == [CATEGORY_PERSISTENCE]
        assert flags[0].severity == "high"
    assert _classify("GetUser", "iam.amazonaws.com") == []


def test_ses_and_bedrock():
    ses = _classify("SendRawEmail", "ses.amazonaws.com")
    assert ses[0].category == CATEGORY_EMAIL and ses[0].severity == "high"
    assert _classify("GetSendQuota", "ses.amazonaws.com")[0].severity == "medium"
    bedrock = _classify("InvokeModel", "bedrock.amazonaws.com")
    assert bedrock[0].category == CATEGORY_LLM and bedrock[0].severity == "high"
    assert _classify("ListFoundationModels", "bedrock.amazonaws.com")[0].severity == "medium"


def test_cryptomining_region_sensitivity():
    away = _classify("RunInstances", "ec2.amazonaws.com", region="eu-north-1")
    assert away[0].category == CATEGORY_CRYPTOMINING and away[0].severity == "high"
    home = _classify("RunInstances", "ec2.amazonaws.com", region="us-east-1")
    assert home[0].severity == "medium"
    no_homes = _classify("RequestSpotInstances", "ec2.amazonaws.com", region="eu-north-1", home_regions=[])
    assert no_homes[0].severity == "medium"


def test_discovery_only_from_unfamiliar_non_aws_ips():
    assert _classify("GetCallerIdentity", "sts.amazonaws.com")[0].category == CATEGORY_DISCOVERY
    assert _classify("GetCallerIdentity", "sts.amazonaws.com", known_ips=["203.0.113.9"]) == []
    assert _classify("ListBuckets", "s3.amazonaws.com", source_ip="cloudformation.amazonaws.com") == []
    assert _classify("ListBuckets", "s3.amazonaws.com", source_ip="AWS Internal") == []


def test_failed_calls_are_marked():
    flags = _classify("CreateUser", "iam.amazonaws.com", error_code="AccessDenied")
    assert flags[0].failed and "call failed: AccessDenied" in flags[0].reason


def test_verdicts():
    high = _classify("CreateUser", "iam.amazonaws.com")
    low = _classify("ListBuckets", "s3.amazonaws.com")
    assert verdict_for(high, 1) == "suspicious"
    assert verdict_for(low, 1) == "inconclusive"
    assert verdict_for([], 0) == "inconclusive"
    assert verdict_for([], 5) == "likely clean"
    assert verdict_for([], 5, had_errors=True) == "inconclusive"
