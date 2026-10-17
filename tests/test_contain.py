from __future__ import annotations

import pytest

from keyleak.contain import contain
from keyleak.errors import ConfirmationRequired, KeyleakError, PermissionDenied, RefusedLeakedKey

from conftest import LEAKED, NOW, OWNER, StubFactory, key_last_used, key_meta

UPDATE = {"UserName": OWNER, "AccessKeyId": LEAKED, "Status": "Inactive"}


def test_refuses_without_confirm_and_makes_no_calls(factory: StubFactory):
    with pytest.raises(ConfirmationRequired) as info:
        contain(factory, LEAKED, confirm=False)
    assert "--confirm" in str(info.value)
    assert "Nothing was done" in str(info.value)


def test_deactivates_only_the_one_key(factory: StubFactory):
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, "Active"), key_meta(OWNER, "AKIAOTHERKEY00000001", "Active")]}, {"UserName": OWNER})
    iam.add_response("update_access_key", {}, UPDATE)
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, "Inactive"), key_meta(OWNER, "AKIAOTHERKEY00000001", "Active")]}, {"UserName": OWNER})

    result = contain(factory, LEAKED, confirm=True, sleep=lambda _s: None, now=NOW)

    assert result.changed is True
    assert result.verified is True
    assert result.previous_status == "Active"
    assert result.new_status == "Inactive"
    assert result.user_name == OWNER
    assert "Status=Inactive" in result.to_dict()["aws_call"]


def test_already_inactive_is_a_no_op(factory: StubFactory):
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, "Inactive")]}, {"UserName": OWNER})
    result = contain(factory, LEAKED, confirm=True, sleep=lambda _s: None, now=NOW)
    assert result.changed is False
    assert result.verified is True


def test_update_denied_is_clear_and_says_key_still_active(factory: StubFactory):
    iam = factory.stub("iam")
    iam.add_response("get_access_key_last_used", key_last_used(OWNER), {"AccessKeyId": LEAKED})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [key_meta(OWNER, LEAKED, "Active")]}, {"UserName": OWNER})
    iam.add_client_error("update_access_key", "AccessDenied", "not authorized", 403, expected_params=UPDATE)
    with pytest.raises(PermissionDenied) as info:
        contain(factory, LEAKED, confirm=True, sleep=lambda _s: None)
    assert "still active" in str(info.value)


def test_unknown_key(factory: StubFactory):
    factory.stub("iam").add_client_error("get_access_key_last_used", "NoSuchEntity", "nope", 404, expected_params={"AccessKeyId": LEAKED})
    with pytest.raises(KeyleakError) as info:
        contain(factory, LEAKED, confirm=True, sleep=lambda _s: None)
    assert "Nothing was changed" in str(info.value)


def test_refuses_to_contain_with_the_leaked_key_itself():
    factory = StubFactory(credential_key=LEAKED)
    with pytest.raises(RefusedLeakedKey):
        contain(factory, LEAKED, confirm=True)
    factory.assert_done()
