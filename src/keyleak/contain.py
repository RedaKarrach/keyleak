"""keyleak contain: deactivate the leaked key. The ONLY command that changes anything.

It sets the key's status to Inactive (not deleted, so CloudTrail lookups and a later
rollback still work). It refuses without --confirm, and it never touches anything
other than that one key. Cleaning up what the attacker created is deliberately left
to a human with the report in hand.

SAFETY RULE: the deactivation call is made with the caller's own credentials; the
leaked key is only the target.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from botocore.exceptions import BotoCoreError, ClientError

from . import aws
from .aws import ClientFactory, call_with_backoff
from .errors import ConfirmationRequired, KeyleakError, PermissionDenied


@dataclass
class ContainResult:
    access_key_id: str
    user_name: str
    previous_status: str
    new_status: str
    changed: bool
    verified: bool
    at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": "deactivate_access_key",
            "access_key_id": self.access_key_id,
            "user_name": self.user_name,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "changed": self.changed,
            "verified": self.verified,
            "at": self.at.isoformat(),
            "aws_call": (
                f"iam:UpdateAccessKey UserName={self.user_name} "
                f"AccessKeyId={self.access_key_id} Status=Inactive"
            ),
        }


def _key_status(iam: Any, user_name: str, key_id: str, sleep: Callable[[float], None]) -> str | None:
    marker: str | None = None
    while True:
        params: dict[str, Any] = {"UserName": user_name}
        if marker:
            params["Marker"] = marker
        resp = call_with_backoff(lambda: iam.list_access_keys(**params), sleep=sleep)
        for meta in resp.get("AccessKeyMetadata", []) or []:
            if meta.get("AccessKeyId") == key_id:
                return str(meta.get("Status", ""))
        if resp.get("IsTruncated") and resp.get("Marker"):
            marker = resp["Marker"]
            continue
        return None


def contain(
    factory: ClientFactory,
    access_key_id: str,
    *,
    confirm: bool,
    sleep: Callable[[float], None] = time.sleep,
    now: datetime | None = None,
) -> ContainResult:
    key = aws.validate_access_key_id(access_key_id)
    if not confirm:
        raise ConfirmationRequired(
            f"contain changes your AWS account: it would set access key {key} to Inactive. "
            "Nothing was done. Re-run with --confirm to go ahead."
        )
    aws.refuse_if_using_leaked_key(factory, key)
    when = now or datetime.now(timezone.utc)
    iam = factory.client("iam")

    try:
        resp = call_with_backoff(lambda: iam.get_access_key_last_used(AccessKeyId=key), sleep=sleep)
    except ClientError as exc:
        aws.raise_if_fatal(exc, what="iam:GetAccessKeyLastUsed")
        if aws.is_access_denied(exc):
            raise PermissionDenied(
                "contain needs iam:GetAccessKeyLastUsed, iam:ListAccessKeys and "
                "iam:UpdateAccessKey. Nothing was changed."
            ) from exc
        if aws.error_code(exc) == "NoSuchEntity":
            raise KeyleakError(
                f"IAM has no access key {key}. It was already deleted, or it belongs to a "
                "different AWS account. Nothing was changed."
            ) from exc
        raise KeyleakError(aws.friendly_error(exc, what="iam:GetAccessKeyLastUsed")) from exc
    except BotoCoreError as exc:
        raise KeyleakError(aws.friendly_error(exc, what="iam:GetAccessKeyLastUsed")) from exc

    user_name = resp.get("UserName")
    if not user_name:
        raise KeyleakError(
            f"Could not work out which IAM user owns {key}, so nothing was changed. "
            "Deactivate it in the IAM console instead."
        )

    try:
        previous = _key_status(iam, user_name, key, sleep) or "unknown"
        if previous == "Inactive":
            return ContainResult(
                access_key_id=key,
                user_name=user_name,
                previous_status=previous,
                new_status="Inactive",
                changed=False,
                verified=True,
                at=when,
            )
        # The one and only write keyleak ever makes.
        call_with_backoff(
            lambda: iam.update_access_key(UserName=user_name, AccessKeyId=key, Status="Inactive"),
            sleep=sleep,
        )
        after = _key_status(iam, user_name, key, sleep) or "unknown"
    except ClientError as exc:
        aws.raise_if_fatal(exc, what="iam:UpdateAccessKey")
        if aws.is_access_denied(exc):
            raise PermissionDenied(
                "Permission denied for iam:UpdateAccessKey. The key is still active. Attach "
                "docs/keyleak-contain-policy.json to the identity running keyleak, or "
                "deactivate the key in the IAM console."
            ) from exc
        raise KeyleakError(aws.friendly_error(exc, what="iam:UpdateAccessKey")) from exc
    except BotoCoreError as exc:
        raise KeyleakError(aws.friendly_error(exc, what="iam:UpdateAccessKey")) from exc

    return ContainResult(
        access_key_id=key,
        user_name=user_name,
        previous_status=previous,
        new_status=after,
        changed=True,
        verified=(after == "Inactive"),
        at=when,
    )
