"""keyleak investigate: what did the leaked key do, and what did it create.

Read-only. Walks CloudTrail event history for an access key ID across every region,
flags attacker behaviour, and then THE PIVOT: if the attacker created new users or
keys, those get investigated too (breadth-first, with a depth limit and a visited
set so loops cannot happen).

SAFETY RULE: the leaked key ID is just a string we search for. All AWS calls use the
caller's own credentials via the ClientFactory. See aws.py.
"""

from __future__ import annotations

import json
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator

from botocore.exceptions import BotoCoreError, ClientError

from . import aws
from .aws import ClientFactory, call_with_backoff
from .errors import CredentialsProblem, PermissionDenied
from .rules import CATEGORY_ORDER, SEVERITY_ORDER, Flag, classify_event, is_aws_internal_ip, verdict_for

# CloudTrail event history (LookupEvents) only goes back 90 days. Anything older is
# gone unless the account has a trail writing to S3, which keyleak does not read.
MAX_LOOKBACK_DAYS = 90
LOOKUP_PAGE_SIZE = 50
DEFAULT_MAX_DEPTH = 3

KIND_KEY = "AccessKeyId"
KIND_USER = "Username"


@dataclass(frozen=True)
class Identity:
    """Something CloudTrail can look up: an access key ID or an IAM user name."""

    kind: str  # KIND_KEY or KIND_USER
    value: str

    @property
    def label(self) -> str:
        return f"key {self.value}" if self.kind == KIND_KEY else f"user {self.value}"

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value}


@dataclass
class Event:
    """One CloudTrail event, flattened from the LookupEvents response."""

    event_id: str
    time: datetime
    name: str
    source: str
    region: str
    source_ip: str
    user_agent: str
    access_key_id: str
    username: str
    identity_arn: str
    error_code: str | None
    read_only: bool
    request_parameters: dict[str, Any]
    response_elements: dict[str, Any]
    resources: list[dict[str, str]]

    @classmethod
    def from_lookup(cls, raw: dict[str, Any], *, region: str) -> "Event":
        detail: dict[str, Any] = {}
        payload = raw.get("CloudTrailEvent")
        if payload:
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    detail = parsed
            except (TypeError, ValueError):
                detail = {}
        when = raw.get("EventTime")
        if isinstance(when, datetime):
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
        else:
            when = _parse_time(detail.get("eventTime")) or datetime.now(timezone.utc)
        user_identity = detail.get("userIdentity") or {}
        request = detail.get("requestParameters")
        response = detail.get("responseElements")
        return cls(
            event_id=str(raw.get("EventId") or detail.get("eventID") or ""),
            time=when,
            name=str(raw.get("EventName") or detail.get("eventName") or ""),
            source=str(raw.get("EventSource") or detail.get("eventSource") or ""),
            region=str(detail.get("awsRegion") or region),
            source_ip=str(detail.get("sourceIPAddress") or ""),
            user_agent=str(detail.get("userAgent") or ""),
            access_key_id=str(raw.get("AccessKeyId") or user_identity.get("accessKeyId") or ""),
            username=str(raw.get("Username") or user_identity.get("userName") or ""),
            identity_arn=str(user_identity.get("arn") or ""),
            error_code=detail.get("errorCode") or None,
            read_only=str(raw.get("ReadOnly", "")).lower() == "true",
            request_parameters=request if isinstance(request, dict) else {},
            response_elements=response if isinstance(response, dict) else {},
            resources=[
                {"type": str(r.get("ResourceType", "")), "name": str(r.get("ResourceName", ""))}
                for r in raw.get("Resources", []) or []
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "time": self.time.isoformat(),
            "name": self.name,
            "source": self.source,
            "region": self.region,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "access_key_id": self.access_key_id,
            "username": self.username,
            "identity_arn": self.identity_arn,
            "error_code": self.error_code,
            "read_only": self.read_only,
            "resources": self.resources,
        }


@dataclass
class KeyInfo:
    access_key_id: str
    status: str
    created: datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_key_id": self.access_key_id,
            "status": self.status,
            "created": self.created.isoformat() if self.created else None,
        }


@dataclass
class IdentityReport:
    """Everything we learned about one key or user."""

    identity: Identity
    depth: int
    discovered_via: str
    user_name: str | None = None
    user_arn: str | None = None
    user_created: datetime | None = None
    key_status: str | None = None
    key_created: datetime | None = None
    key_last_used: datetime | None = None
    iam_note: str | None = None
    iam_keys: list[KeyInfo] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    verdict: str = "inconclusive"
    region_errors: dict[str, str] = field(default_factory=dict)
    pivots: list[Identity] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "depth": self.depth,
            "discovered_via": self.discovered_via,
            "user_name": self.user_name,
            "user_arn": self.user_arn,
            "user_created": self.user_created.isoformat() if self.user_created else None,
            "key_status": self.key_status,
            "key_created": self.key_created.isoformat() if self.key_created else None,
            "key_last_used": self.key_last_used.isoformat() if self.key_last_used else None,
            "iam_note": self.iam_note,
            "iam_keys": [k.to_dict() for k in self.iam_keys],
            "events": [e.to_dict() for e in self.events],
            "flags": [f.to_dict() for f in self.flags],
            "verdict": self.verdict,
            "region_errors": dict(self.region_errors),
            "pivots": [p.to_dict() for p in self.pivots],
        }


@dataclass
class Investigation:
    root: Identity
    started_at: datetime
    window_start: datetime
    window_end: datetime
    lookback_days: int
    regions: list[str]
    home_regions: list[str]
    known_ips: list[str]
    max_depth: int
    pivot_enabled: bool
    reports: list[IdentityReport] = field(default_factory=list)
    skipped_pivots: list[dict[str, str]] = field(default_factory=list)
    caller: dict[str, str] | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def root_report(self) -> IdentityReport | None:
        return self.reports[0] if self.reports else None

    @property
    def all_events(self) -> list[Event]:
        seen: set[str] = set()
        out: list[Event] = []
        for report in self.reports:
            for ev in report.events:
                if ev.event_id and ev.event_id in seen:
                    continue
                seen.add(ev.event_id)
                out.append(ev)
        out.sort(key=lambda e: e.time)
        return out

    @property
    def all_flags(self) -> list[Flag]:
        seen: set[tuple[str, str]] = set()
        out: list[Flag] = []
        for report in self.reports:
            for flag in report.flags:
                key = (flag.event_id, flag.category)
                if key in seen:
                    continue
                seen.add(key)
                out.append(flag)
        out.sort(
            key=lambda f: (
                CATEGORY_ORDER.index(f.category) if f.category in CATEGORY_ORDER else 99,
                SEVERITY_ORDER.get(f.severity, 9),
                f.time,
            )
        )
        return out

    @property
    def verdict(self) -> str:
        verdicts = [r.verdict for r in self.reports]
        if "suspicious" in verdicts:
            return "suspicious"
        if not verdicts or not self.reports[0].events:
            return "inconclusive"
        if all(v == "likely clean" for v in verdicts):
            return "likely clean"
        return "inconclusive"

    @property
    def source_ips(self) -> Counter:
        return Counter(e.source_ip for e in self.all_events if e.source_ip and not is_aws_internal_ip(e.source_ip))

    @property
    def suspect_ips(self) -> list[str]:
        ips = {f.source_ip for f in self.all_flags if f.source_ip and not is_aws_internal_ip(f.source_ip)}
        return sorted(ips)

    @property
    def user_agents(self) -> Counter:
        return Counter(e.user_agent for e in self.all_events if e.user_agent)

    @property
    def regions_with_activity(self) -> list[str]:
        return sorted({e.region for e in self.all_events if e.region})

    @property
    def first_flag_time(self) -> datetime | None:
        flags = self.all_flags
        return min(f.time for f in flags) if flags else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "investigate",
            "root": self.root.to_dict(),
            "started_at": self.started_at.isoformat(),
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "lookback_days": self.lookback_days,
            "regions": list(self.regions),
            "home_regions": list(self.home_regions),
            "known_ips": list(self.known_ips),
            "max_depth": self.max_depth,
            "pivot_enabled": self.pivot_enabled,
            "verdict": self.verdict,
            "caller": self.caller,
            "notes": list(self.notes),
            "reports": [r.to_dict() for r in self.reports],
            "skipped_pivots": list(self.skipped_pivots),
            "timeline": [e.to_dict() for e in self.all_events],
            "flags": [f.to_dict() for f in self.all_flags],
            "suspect_ips": self.suspect_ips,
            "source_ips": dict(self.source_ips),
            "user_agents": dict(self.user_agents),
            "regions_with_activity": self.regions_with_activity,
            "first_flag_time": self.first_flag_time.isoformat() if self.first_flag_time else None,
        }


class Investigator:
    """Runs one investigation. Construct it once, call `run(key_id)`."""

    def __init__(
        self,
        factory: ClientFactory,
        *,
        regions: list[str],
        lookback_days: int = MAX_LOOKBACK_DAYS,
        max_depth: int = DEFAULT_MAX_DEPTH,
        known_ips: list[str] | tuple[str, ...] = (),
        home_regions: list[str] | tuple[str, ...] = (),
        pivot: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        page_pause: float = 0.6,
        now: datetime | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        if not regions:
            raise ValueError("at least one region is required")
        self.factory = factory
        self.regions = list(regions)
        self.lookback_days = max(1, min(int(lookback_days), MAX_LOOKBACK_DAYS))
        self.max_depth = max(0, int(max_depth))
        self.known_ips = [ip.strip() for ip in known_ips if ip and ip.strip()]
        self.home_regions = [r.strip() for r in home_regions if r and r.strip()]
        self.pivot = pivot
        self.sleep = sleep
        self.page_pause = page_pause
        self.now = now or datetime.now(timezone.utc)
        self.progress = progress or (lambda _msg: None)
        self._keys_cache: dict[str, list[KeyInfo]] = {}

    # -- public -----------------------------------------------------------------

    def run(self, access_key_id: str) -> Investigation:
        key = aws.validate_access_key_id(access_key_id)
        aws.refuse_if_using_leaked_key(self.factory, key)

        window_end = self.now
        window_start = window_end - timedelta(days=self.lookback_days)
        inv = Investigation(
            root=Identity(KIND_KEY, key),
            started_at=self.now,
            window_start=window_start,
            window_end=window_end,
            lookback_days=self.lookback_days,
            regions=self.regions,
            home_regions=self.home_regions,
            known_ips=self.known_ips,
            max_depth=self.max_depth,
            pivot_enabled=self.pivot,
        )
        inv.notes.append(
            f"CloudTrail event history only covers the last {MAX_LOOKBACK_DAYS} days. "
            f"This run looked at {window_start:%Y-%m-%d} to {window_end:%Y-%m-%d} (UTC)."
        )
        if key.startswith("ASIA"):
            inv.notes.append(
                "This is a temporary (ASIA) key. It expires on its own, but anything it "
                "created does not."
            )
        if not self.known_ips:
            inv.notes.append(
                "No --known-ip given, so every discovery call (GetCallerIdentity, ListBuckets, "
                "ListUsers) from outside AWS is marked low-severity. Pass your own IPs to quiet those."
            )

        queue: deque[tuple[Identity, int, str]] = deque([(inv.root, 0, "the key you reported")])
        visited: set[Identity] = set()
        while queue:
            identity, depth, via = queue.popleft()
            if identity in visited:
                continue
            visited.add(identity)
            report = self._investigate_identity(identity, depth, via, inv)
            inv.reports.append(report)

            for pivot, how in self._pivots_from(report):
                if pivot == identity:
                    continue
                if pivot not in report.pivots:
                    report.pivots.append(pivot)
                if pivot in visited or any(pivot == q[0] for q in queue):
                    continue
                if not self.pivot:
                    inv.skipped_pivots.append(
                        {"identity": pivot.label, "found_via": how, "reason": "pivoting disabled (--no-pivot)"}
                    )
                    continue
                if depth + 1 > self.max_depth:
                    inv.skipped_pivots.append(
                        {
                            "identity": pivot.label,
                            "found_via": how,
                            "reason": f"depth limit {self.max_depth} reached (raise --max-depth to follow it)",
                        }
                    )
                    continue
                queue.append((pivot, depth + 1, how))
        return inv

    # -- per identity -------------------------------------------------------------

    def _investigate_identity(self, identity: Identity, depth: int, via: str, inv: Investigation) -> IdentityReport:
        report = IdentityReport(identity=identity, depth=depth, discovered_via=via)
        self._resolve_iam(report)

        events: list[Event] = []
        seen: set[str] = set()
        for region in self.regions:
            self.progress(f"CloudTrail {region}: looking up {identity.label}")
            try:
                for ev in self._lookup(region, identity, inv.window_start, inv.window_end):
                    if ev.event_id and ev.event_id in seen:
                        continue
                    seen.add(ev.event_id)
                    events.append(ev)
            except ClientError as exc:
                code = aws.error_code(exc)
                report.region_errors[region] = f"{code}: {aws.error_message(exc)}"
            except BotoCoreError as exc:
                report.region_errors[region] = f"unreachable: {exc}"

        self._raise_if_every_region_failed(report)

        events.sort(key=lambda e: e.time)
        report.events = events
        report.flags = [
            flag
            for ev in events
            for flag in classify_event(
                event_id=ev.event_id,
                event_name=ev.name,
                event_source=ev.source,
                region=ev.region,
                time=ev.time,
                source_ip=ev.source_ip,
                identity=identity.value,
                error_code=ev.error_code,
                known_ips=self.known_ips,
                home_regions=self.home_regions,
            )
        ]
        report.verdict = verdict_for(report.flags, len(events), had_errors=bool(report.region_errors))
        return report

    def _raise_if_every_region_failed(self, report: IdentityReport) -> None:
        if len(report.region_errors) < len(self.regions):
            return
        codes = {msg.split(":", 1)[0] for msg in report.region_errors.values()}
        if codes and codes <= aws.ACCESS_DENIED_CODES:
            raise PermissionDenied(
                "cloudtrail:LookupEvents was denied in every region, so there is nothing to "
                "investigate. Attach docs/keyleak-readonly-policy.json to the identity you are "
                "running keyleak with (not the leaked key). If CloudTrail is blocked by an "
                "organisation policy, ask whoever manages the account."
            )
        if codes and codes <= aws.BAD_CREDENTIAL_CODES:
            raise CredentialsProblem(
                "AWS rejected your credentials in every region (" + ", ".join(sorted(codes)) + "). "
                "They may be expired. Refresh them (for example `aws sso login`) and try again."
            )

    def _lookup(self, region: str, identity: Identity, start: datetime, end: datetime) -> Iterator[Event]:
        cloudtrail = self.factory.client("cloudtrail", region_name=region)
        params: dict[str, Any] = {
            "LookupAttributes": [{"AttributeKey": identity.kind, "AttributeValue": identity.value}],
            "StartTime": start,
            "EndTime": end,
            "MaxResults": LOOKUP_PAGE_SIZE,
        }
        while True:
            resp = call_with_backoff(lambda: cloudtrail.lookup_events(**params), sleep=self.sleep)
            for raw in resp.get("Events", []) or []:
                yield Event.from_lookup(raw, region=region)
            token = resp.get("NextToken")
            if not token:
                return
            params["NextToken"] = token
            # LookupEvents is rate limited to about two calls per second per region.
            self.sleep(self.page_pause)

    def _resolve_iam(self, report: IdentityReport) -> None:
        """Fill in who owns the key / when the user was created. Best effort."""
        identity = report.identity
        iam = self.factory.client("iam")
        try:
            if identity.kind == KIND_KEY:
                resp = call_with_backoff(
                    lambda: iam.get_access_key_last_used(AccessKeyId=identity.value), sleep=self.sleep
                )
                report.user_name = resp.get("UserName") or None
                last_used = resp.get("AccessKeyLastUsed") or {}
                stamp = last_used.get("LastUsedDate")
                report.key_last_used = stamp if isinstance(stamp, datetime) else None
                if report.user_name:
                    for info in self._list_keys(iam, report.user_name):
                        if info.access_key_id == identity.value:
                            report.key_status = info.status
                            report.key_created = info.created
            else:
                resp = call_with_backoff(lambda: iam.get_user(UserName=identity.value), sleep=self.sleep)
                user = resp.get("User") or {}
                report.user_name = identity.value
                report.user_arn = user.get("Arn")
                created = user.get("CreateDate")
                report.user_created = created if isinstance(created, datetime) else None
                report.iam_keys = self._list_keys(iam, identity.value)
        except ClientError as exc:
            aws.raise_if_fatal(exc, what="IAM lookups")
            code = aws.error_code(exc)
            if aws.is_access_denied(exc):
                report.iam_note = (
                    "No IAM read permission (iam:GetAccessKeyLastUsed / iam:GetUser / "
                    "iam:ListAccessKeys), so the owner could not be resolved. The CloudTrail "
                    "timeline still works."
                )
            elif code == "NoSuchEntity":
                report.iam_note = (
                    f"IAM has no record of {identity.label}. It was already deleted, or it "
                    "belongs to a different AWS account."
                )
            else:
                report.iam_note = aws.friendly_error(exc, what="IAM lookups")
        except BotoCoreError as exc:
            report.iam_note = aws.friendly_error(exc, what="IAM lookups")

    def _list_keys(self, iam: Any, user_name: str) -> list[KeyInfo]:
        if user_name in self._keys_cache:
            return self._keys_cache[user_name]
        keys: list[KeyInfo] = []
        marker: str | None = None
        while True:
            params: dict[str, Any] = {"UserName": user_name}
            if marker:
                params["Marker"] = marker
            resp = call_with_backoff(lambda: iam.list_access_keys(**params), sleep=self.sleep)
            for item in resp.get("AccessKeyMetadata", []) or []:
                created = item.get("CreateDate")
                keys.append(
                    KeyInfo(
                        access_key_id=str(item.get("AccessKeyId", "")),
                        status=str(item.get("Status", "")),
                        created=created if isinstance(created, datetime) else None,
                    )
                )
            if resp.get("IsTruncated") and resp.get("Marker"):
                marker = resp["Marker"]
                continue
            break
        self._keys_cache[user_name] = keys
        return keys

    # -- the pivot --------------------------------------------------------------

    def _pivots_from(self, report: IdentityReport) -> list[tuple[Identity, str]]:
        """New identities the attacker may now control, found in this report's events.

        Deleting the leaked key does nothing about these. Each becomes its own
        investigation (depth + 1).
        """
        found: list[tuple[Identity, str]] = []
        who = report.identity.label

        for ev in report.events:
            if ev.error_code:
                continue  # a failed CreateUser created nothing
            stamp = f"{ev.time:%Y-%m-%d %H:%M:%S}Z"
            if ev.source == "iam.amazonaws.com":
                if ev.name == "CreateAccessKey":
                    key_id = (ev.response_elements.get("accessKey") or {}).get("accessKeyId")
                    if key_id:
                        found.append((Identity(KIND_KEY, str(key_id)), f"CreateAccessKey by {who} at {stamp}"))
                elif ev.name == "CreateUser":
                    user = (ev.response_elements.get("user") or {}).get("userName") or ev.request_parameters.get("userName")
                    if user:
                        found.append((Identity(KIND_USER, str(user)), f"CreateUser by {who} at {stamp}"))
                elif ev.name == "CreateLoginProfile":
                    user = ev.request_parameters.get("userName")
                    if user:
                        found.append((Identity(KIND_USER, str(user)), f"CreateLoginProfile (console password) by {who} at {stamp}"))
            elif ev.source == "sts.amazonaws.com" and ev.name == "AssumeRole":
                key_id = (ev.response_elements.get("credentials") or {}).get("accessKeyId")
                if key_id:
                    found.append((Identity(KIND_KEY, str(key_id)), f"AssumeRole by {who} at {stamp} (temporary key)"))

        # Keys IAM lists on a user we are investigating. Catches keys whose
        # CreateAccessKey event has already aged out of the 90-day window.
        for info in report.iam_keys:
            found.append((Identity(KIND_KEY, info.access_key_id), f"listed by IAM on {who}"))

        return found


def _parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
