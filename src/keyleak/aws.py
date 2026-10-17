"""Thin layer over boto3: client creation, retries, and friendly error mapping.

SAFETY RULE (the most important thing in this file):
keyleak never authenticates with the leaked key. Every client built here comes from
the caller's OWN credentials via the normal boto3 chain (environment variables,
~/.aws/credentials, SSO, an instance role...). The leaked access key ID is only ever
passed around as a plain string argument so we can look it up in CloudTrail and IAM.
`refuse_if_using_leaked_key` makes sure nobody accidentally does the opposite.
"""

from __future__ import annotations

import random
import re
import time
from typing import Any, Callable, Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    NoRegionError,
    PartialCredentialsError,
    ProfileNotFound,
)

from .errors import CredentialsProblem, InvalidKeyId, KeyleakError, RefusedLeakedKey

# AKIA = long-term IAM user key. ASIA = temporary STS key. Both are 20 characters.
ACCESS_KEY_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")

THROTTLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "RateExceeded",
        "ProvisionedThroughputExceededException",
        "RequestThrottled",
        "RequestThrottledException",
        "SlowDown",
    }
)

ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnauthorizedAccess",
        "AuthorizationError",
        "NotAuthorized",
    }
)

BAD_CREDENTIAL_CODES = frozenset(
    {
        "InvalidClientTokenId",
        "UnrecognizedClientException",
        "ExpiredToken",
        "ExpiredTokenException",
        "SignatureDoesNotMatch",
        "AuthFailure",
        "InvalidSignatureException",
    }
)

# Used only when ec2:DescribeRegions is not allowed. Commercial partition, opt-in
# regions left out because querying a region that is not enabled fails noisily.
# ASSUMPTION: GovCloud and China partitions are out of scope for the fallback list.
FALLBACK_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "ap-south-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "sa-east-1",
]

# boto3's own adaptive retry mode handles a first layer of throttling. keyleak adds
# its own backoff on top in `call_with_backoff` because CloudTrail LookupEvents is
# limited to a couple of requests per second and we query many regions.
_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 5}, user_agent_extra="keyleak")


class ClientFactory(Protocol):
    """Anything that hands out boto3-shaped clients. Tests swap in stubbed clients."""

    def client(self, service: str, region_name: str | None = None) -> Any: ...

    def default_region(self) -> str: ...

    def credential_access_key(self) -> str | None: ...


class BotoClientFactory:
    """Builds real boto3 clients from the caller's own credentials.

    `profile` and `region` are passed straight to boto3.Session; everything else is
    the default credential chain. Nothing here ever reads the leaked key.
    """

    def __init__(self, profile: str | None = None, region: str | None = None) -> None:
        try:
            self.session = boto3.Session(profile_name=profile, region_name=region)
        except ProfileNotFound as exc:
            raise CredentialsProblem(
                f"AWS profile '{profile}' was not found in your ~/.aws/config or credentials file."
            ) from exc
        self._cache: dict[tuple[str, str | None], Any] = {}

    def default_region(self) -> str:
        return self.session.region_name or "us-east-1"

    def client(self, service: str, region_name: str | None = None) -> Any:
        key = (service, region_name)
        if key not in self._cache:
            region = region_name or self.default_region()
            try:
                self._cache[key] = self.session.client(service, region_name=region, config=_CONFIG)
            except NoRegionError as exc:  # pragma: no cover - defensive
                raise CredentialsProblem(
                    "No AWS region configured. Set AWS_DEFAULT_REGION or pass --region."
                ) from exc
        return self._cache[key]

    def credential_access_key(self) -> str | None:
        try:
            creds = self.session.get_credentials()
        except BotoCoreError:
            return None
        if creds is None:
            return None
        frozen = creds.get_frozen_credentials()
        return frozen.access_key


def validate_access_key_id(value: str) -> str:
    """Return the key ID if it looks like one, otherwise raise a clear error."""
    candidate = (value or "").strip()
    if ACCESS_KEY_RE.match(candidate):
        return candidate
    raise InvalidKeyId(
        f"'{value}' does not look like an AWS access key ID. Expected 20 characters "
        "starting with AKIA (long-term key) or ASIA (temporary key), for example "
        "AKIAIOSFODNN7EXAMPLE. Pass only the key ID, never the secret."
    )


def refuse_if_using_leaked_key(factory: ClientFactory, leaked_key_id: str) -> None:
    """Hard stop if the credentials keyleak is about to use ARE the leaked key.

    Using a compromised key to investigate itself is exactly what we tell people not
    to do: it muddies the CloudTrail timeline and it may already be quarantined.
    """
    current = factory.credential_access_key()
    if current and current == leaked_key_id:
        raise RefusedLeakedKey(
            "Refusing to run: the AWS credentials keyleak would use are the leaked key "
            f"itself ({leaked_key_id}). keyleak must run with a DIFFERENT identity, such "
            "as an admin or read-only user that was never exposed. Fix your AWS_PROFILE "
            "or environment variables and try again."
        )


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def error_message(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Message", "")) or str(exc)


def is_throttle(exc: BaseException) -> bool:
    return isinstance(exc, ClientError) and error_code(exc) in THROTTLE_CODES


def is_access_denied(exc: BaseException) -> bool:
    return isinstance(exc, ClientError) and error_code(exc) in ACCESS_DENIED_CODES


def is_bad_credentials(exc: BaseException) -> bool:
    return isinstance(exc, ClientError) and error_code(exc) in BAD_CREDENTIAL_CODES


def call_with_backoff(
    fn: Callable[[], Any],
    *,
    max_attempts: int = 6,
    sleep: Callable[[float], None] = time.sleep,
    base_delay: float = 0.5,
    max_delay: float = 20.0,
) -> Any:
    """Call `fn`, retrying throttling errors with exponential backoff and jitter."""
    attempt = 0
    while True:
        try:
            return fn()
        except ClientError as exc:
            attempt += 1
            if not is_throttle(exc) or attempt >= max_attempts:
                raise
            delay = min(base_delay * (2 ** (attempt - 1)), max_delay) + random.uniform(0, 0.3)
            sleep(delay)


def friendly_error(exc: BaseException, *, what: str = "an AWS call") -> str:
    """Turn a boto exception into one readable sentence."""
    if isinstance(exc, NoCredentialsError):
        return (
            "No AWS credentials found. keyleak uses YOUR OWN credentials (not the leaked "
            "key): configure a profile with `aws configure`, log in with `aws sso login`, "
            "or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for a safe identity."
        )
    if isinstance(exc, PartialCredentialsError):
        return "AWS credentials are incomplete (key ID without secret, or similar). Check your profile."
    if isinstance(exc, NoRegionError):
        return "No AWS region configured. Set AWS_DEFAULT_REGION or pass --region."
    if isinstance(exc, EndpointConnectionError):
        return f"Could not reach AWS for {what}: {exc}. Check your network, VPN, or proxy."
    if isinstance(exc, ClientError):
        code = error_code(exc)
        if code in ACCESS_DENIED_CODES:
            return (
                f"Permission denied for {what} ({code}). Attach the read-only policy from "
                "docs/keyleak-readonly-policy.json to the identity you are running keyleak with."
            )
        if code in BAD_CREDENTIAL_CODES:
            return (
                f"AWS rejected your credentials ({code}). They may be expired or invalid. "
                "Refresh them (for example `aws sso login`) and try again."
            )
        if code in THROTTLE_CODES:
            return f"AWS kept throttling {what} even after retries. Wait a minute and try again."
        return f"AWS error during {what}: {code}: {error_message(exc)}"
    if isinstance(exc, KeyleakError):
        return str(exc)
    return f"Unexpected problem during {what}: {exc}"


def raise_if_fatal(exc: BaseException, *, what: str) -> None:
    """Convert credential problems into KeyleakError; leave everything else alone."""
    if isinstance(exc, (NoCredentialsError, PartialCredentialsError, NoRegionError)):
        raise CredentialsProblem(friendly_error(exc, what=what)) from exc
    if is_bad_credentials(exc):
        raise CredentialsProblem(friendly_error(exc, what=what)) from exc


def list_regions(factory: ClientFactory) -> list[str]:
    """All regions enabled for the account. Falls back to a static list if denied."""
    try:
        ec2 = factory.client("ec2", region_name="us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        regions = sorted(r["RegionName"] for r in resp.get("Regions", []))
        return regions or list(FALLBACK_REGIONS)
    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise CredentialsProblem(friendly_error(exc, what="listing regions")) from exc
    except ClientError as exc:
        raise_if_fatal(exc, what="listing regions")
        return list(FALLBACK_REGIONS)
    except BotoCoreError:
        return list(FALLBACK_REGIONS)


def caller_identity(factory: ClientFactory) -> dict[str, str] | None:
    """Who keyleak is running as. Returns None if sts:GetCallerIdentity is not allowed."""
    try:
        sts = factory.client("sts")
        resp = sts.get_caller_identity()
        return {
            "Account": resp.get("Account", ""),
            "Arn": resp.get("Arn", ""),
            "UserId": resp.get("UserId", ""),
        }
    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise CredentialsProblem(friendly_error(exc, what="sts:GetCallerIdentity")) from exc
    except ClientError as exc:
        raise_if_fatal(exc, what="sts:GetCallerIdentity")
        return None
    except BotoCoreError:
        return None
