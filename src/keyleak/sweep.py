"""keyleak sweep: what is still running (and still costing money).

Read-only. Lists running EC2 instances and Lambda functions in every region, plus
IAM users and access keys created after --since. Each resource gets a concern level
so the reader knows what to look at first.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from botocore.exceptions import BotoCoreError, ClientError

from . import aws
from .aws import ClientFactory, call_with_backoff
from .errors import PermissionDenied

CONCERN_ORDER = {"high": 0, "medium": 1, "low": 2}

# Instance families attackers like for mining: GPU, accelerator, FPGA.
HEAVY_FAMILY_PREFIXES = ("p", "g", "inf", "trn", "dl", "f")
BIG_SIZES = (
    "4xlarge",
    "8xlarge",
    "9xlarge",
    "12xlarge",
    "16xlarge",
    "18xlarge",
    "24xlarge",
    "32xlarge",
    "48xlarge",
    "metal",
)


@dataclass
class Resource:
    kind: str  # "EC2 instance" | "Lambda function" | "IAM user" | "IAM access key"
    region: str
    resource_id: str
    created: datetime | None
    concern: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "region": self.region,
            "resource_id": self.resource_id,
            "created": self.created.isoformat() if self.created else None,
            "concern": self.concern,
            "detail": self.detail,
        }


@dataclass
class SweepResult:
    started_at: datetime
    since: datetime
    regions: list[str]
    resources: list[Resource] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {"high": 0, "medium": 0, "low": 0}
        for r in self.resources:
            out[r.concern] = out.get(r.concern, 0) + 1
        return out

    def sorted_resources(self) -> list[Resource]:
        return sorted(
            self.resources,
            key=lambda r: (
                CONCERN_ORDER.get(r.concern, 9),
                -(r.created.timestamp() if r.created else 0),
                r.region,
                r.resource_id,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "sweep",
            "started_at": self.started_at.isoformat(),
            "since": self.since.isoformat(),
            "regions": list(self.regions),
            "resources": [r.to_dict() for r in self.sorted_resources()],
            "errors": dict(self.errors),
            "notes": list(self.notes),
            "counts": self.counts(),
        }


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _is_heavy(instance_type: str) -> bool:
    family = instance_type.split(".")[0]
    for prefix in HEAVY_FAMILY_PREFIXES:
        rest = family[len(prefix) :]
        if family.startswith(prefix) and rest[:1].isdigit():
            return True
    return any(instance_type.endswith(size) for size in BIG_SIZES)


def instance_concern(launch_time: datetime | None, instance_type: str, since: datetime) -> tuple[str, str]:
    new = bool(launch_time and launch_time >= since)
    heavy = _is_heavy(instance_type)
    if new and heavy:
        return "high", f"{instance_type} launched after --since; GPU/large type is the classic mining profile"
    if new:
        return "medium", f"{instance_type} launched after --since"
    if heavy:
        return "low", f"{instance_type} launched before --since (large type, worth a glance)"
    return "low", f"{instance_type} launched before --since"


def parse_lambda_time(value: str | None) -> datetime | None:
    """Lambda returns LastModified like 2026-10-01T12:00:00.000+0000."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


class Sweeper:
    def __init__(
        self,
        factory: ClientFactory,
        *,
        regions: list[str],
        since: datetime,
        sleep: Callable[[float], None] = time.sleep,
        now: datetime | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        if not regions:
            raise ValueError("at least one region is required")
        self.factory = factory
        self.regions = list(regions)
        self.since = _as_utc(since) or datetime.now(timezone.utc)
        self.sleep = sleep
        self.now = now or datetime.now(timezone.utc)
        self.progress = progress or (lambda _msg: None)

    def run(self) -> SweepResult:
        result = SweepResult(started_at=self.now, since=self.since, regions=self.regions)
        denied: list[str] = []
        for region in self.regions:
            self.progress(f"EC2 {region}")
            self._guard(result, f"ec2:{region}", denied, lambda: self._ec2(region, result))
            self.progress(f"Lambda {region}")
            self._guard(result, f"lambda:{region}", denied, lambda: self._lambda(region, result))
        self.progress("IAM users and keys")
        self._guard(result, "iam", denied, lambda: self._iam(result))

        if len(denied) == len(self.regions) * 2 + 1:
            raise PermissionDenied(
                "Every sweep call was denied (ec2:Describe*, lambda:List*, iam:List*). Attach "
                "docs/keyleak-readonly-policy.json to the identity running keyleak."
            )
        if denied:
            result.notes.append(
                f"{len(denied)} call(s) were denied and skipped; see errors. The read-only "
                "policy in docs/keyleak-readonly-policy.json covers all of them."
            )
        result.notes.append(
            "Only EC2, Lambda and IAM are checked. Attackers also use ECS, SageMaker, "
            "Lightsail and Bedrock; check the Billing console's Bill page by service."
        )
        return result

    def _guard(self, result: SweepResult, label: str, denied: list[str], fn: Callable[[], None]) -> None:
        try:
            fn()
        except ClientError as exc:
            aws.raise_if_fatal(exc, what=label)
            if aws.is_access_denied(exc):
                denied.append(label)
            result.errors[label] = f"{aws.error_code(exc)}: {aws.error_message(exc)}"
        except BotoCoreError as exc:
            result.errors[label] = f"unreachable: {exc}"

    def _ec2(self, region: str, result: SweepResult) -> None:
        ec2 = self.factory.client("ec2", region_name=region)
        token: str | None = None
        while True:
            params: dict[str, Any] = {
                "Filters": [{"Name": "instance-state-name", "Values": ["pending", "running"]}],
                "MaxResults": 1000,
            }
            if token:
                params["NextToken"] = token
            resp = call_with_backoff(lambda: ec2.describe_instances(**params), sleep=self.sleep)
            for reservation in resp.get("Reservations", []) or []:
                for inst in reservation.get("Instances", []) or []:
                    launch = _as_utc(inst.get("LaunchTime"))
                    itype = str(inst.get("InstanceType", "?"))
                    concern, detail = instance_concern(launch, itype, self.since)
                    name = next(
                        (t.get("Value") for t in inst.get("Tags", []) or [] if t.get("Key") == "Name"),
                        None,
                    )
                    if name:
                        detail += f'; Name="{name}"'
                    if inst.get("KeyName"):
                        detail += f"; ssh key {inst['KeyName']}"
                    result.resources.append(
                        Resource(
                            kind="EC2 instance",
                            region=region,
                            resource_id=str(inst.get("InstanceId", "?")),
                            created=launch,
                            concern=concern,
                            detail=detail,
                        )
                    )
            token = resp.get("NextToken")
            if not token:
                break

    def _lambda(self, region: str, result: SweepResult) -> None:
        lam = self.factory.client("lambda", region_name=region)
        marker: str | None = None
        while True:
            params: dict[str, Any] = {}
            if marker:
                params["Marker"] = marker
            resp = call_with_backoff(lambda: lam.list_functions(**params), sleep=self.sleep)
            for fn in resp.get("Functions", []) or []:
                modified = parse_lambda_time(fn.get("LastModified"))
                new = bool(modified and modified >= self.since)
                concern = "medium" if new else "low"
                detail = (
                    f"{fn.get('Runtime', '?')}, {'created or modified after' if new else 'untouched since before'} --since"
                )
                result.resources.append(
                    Resource(
                        kind="Lambda function",
                        region=region,
                        resource_id=str(fn.get("FunctionName", "?")),
                        created=modified,
                        concern=concern,
                        detail=detail,
                    )
                )
            marker = resp.get("NextMarker")
            if not marker:
                break

    def _iam(self, result: SweepResult) -> None:
        iam = self.factory.client("iam")
        users: list[dict[str, Any]] = []
        marker: str | None = None
        while True:
            params: dict[str, Any] = {}
            if marker:
                params["Marker"] = marker
            resp = call_with_backoff(lambda: iam.list_users(**params), sleep=self.sleep)
            users.extend(resp.get("Users", []) or [])
            if resp.get("IsTruncated") and resp.get("Marker"):
                marker = resp["Marker"]
                continue
            break

        for user in users:
            name = str(user.get("UserName", "?"))
            created = _as_utc(user.get("CreateDate"))
            user_is_new = bool(created and created >= self.since)
            if user_is_new:
                result.resources.append(
                    Resource(
                        kind="IAM user",
                        region="global",
                        resource_id=name,
                        created=created,
                        concern="high",
                        detail="user created after --since; attackers create users as a backdoor",
                    )
                )
            # Every user's keys are checked, not just new users: a fresh key on an OLD
            # user is the most common backdoor and the easiest one to miss.
            key_marker: str | None = None
            while True:
                kparams: dict[str, Any] = {"UserName": name}
                if key_marker:
                    kparams["Marker"] = key_marker
                kresp = call_with_backoff(lambda: iam.list_access_keys(**kparams), sleep=self.sleep)
                for meta in kresp.get("AccessKeyMetadata", []) or []:
                    kcreated = _as_utc(meta.get("CreateDate"))
                    if not (kcreated and kcreated >= self.since):
                        continue
                    status = str(meta.get("Status", "?"))
                    if user_is_new:
                        detail = f"{status} key on a user that was also created after --since"
                    else:
                        detail = f"{status} key created after --since on EXISTING user {name}"
                    result.resources.append(
                        Resource(
                            kind="IAM access key",
                            region="global",
                            resource_id=str(meta.get("AccessKeyId", "?")),
                            created=kcreated,
                            concern="high" if status == "Active" else "medium",
                            detail=detail,
                        )
                    )
                if kresp.get("IsTruncated") and kresp.get("Marker"):
                    key_marker = kresp["Marker"]
                    continue
                break
