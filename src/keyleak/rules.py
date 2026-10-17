"""What counts as attacker behaviour.

Each CloudTrail event is checked against a handful of categories. The lists are
deliberately short and high-signal; the goal is to answer "what did they do" for a
panicked person, not to be a SIEM.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

CATEGORY_PERSISTENCE = "Persistence"
CATEGORY_CRYPTOMINING = "Cryptomining"
CATEGORY_EMAIL = "Email abuse"
CATEGORY_LLM = "LLM abuse"
CATEGORY_DISCOVERY = "Discovery"

CATEGORY_ORDER = [
    CATEGORY_PERSISTENCE,
    CATEGORY_CRYPTOMINING,
    CATEGORY_LLM,
    CATEGORY_EMAIL,
    CATEGORY_DISCOVERY,
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Events that give the attacker a way back in even after the leaked key is dead.
PERSISTENCE_EVENTS = frozenset(
    {
        "CreateUser",
        "CreateAccessKey",
        "CreateLoginProfile",
        "AttachUserPolicy",
        "PutUserPolicy",
        "UpdateAssumeRolePolicy",
        "CreateRole",
    }
)

# RunInstances is the classic one. The other three are alternative launch paths.
# ASSUMPTION: spot and fleet requests are treated the same as RunInstances.
CRYPTOMINING_EVENTS = frozenset(
    {
        "RunInstances",
        "RequestSpotInstances",
        "RequestSpotFleet",
        "CreateFleet",
    }
)

# Recon calls that are normal from your own machines and suspicious from elsewhere.
DISCOVERY_EVENTS = frozenset({"GetCallerIdentity", "ListBuckets", "ListUsers"})

EMAIL_SOURCES = frozenset({"ses.amazonaws.com"})
EMAIL_HIGH_EVENTS = frozenset(
    {
        "SendEmail",
        "SendRawEmail",
        "SendBulkTemplatedEmail",
        "SendTemplatedEmail",
        "VerifyEmailIdentity",
        "VerifyDomainIdentity",
        "CreateEmailIdentity",
        "UpdateAccountSendingEnabled",
        "PutAccountDetails",
    }
)

LLM_SOURCE_PREFIX = "bedrock"
LLM_HIGH_EVENT_PREFIXES = (
    "Invoke",
    "Converse",
    "CreateModelInvocationJob",
    "PutFoundationModelEntitlement",
)

# Source "IPs" that are really AWS services acting on your behalf.
AWS_INTERNAL_IP_SUFFIXES = (".amazonaws.com", "AWS Internal")


@dataclass(frozen=True)
class Flag:
    category: str
    severity: str  # high | medium | low
    reason: str
    event_id: str
    event_name: str
    event_source: str
    region: str
    time: datetime
    source_ip: str
    identity: str  # the key or user the event was found under
    failed: bool = False

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "reason": self.reason,
            "event_id": self.event_id,
            "event_name": self.event_name,
            "event_source": self.event_source,
            "region": self.region,
            "time": self.time.isoformat(),
            "source_ip": self.source_ip,
            "identity": self.identity,
            "failed": self.failed,
        }


def is_aws_internal_ip(ip: str) -> bool:
    return any(ip.endswith(suffix) for suffix in AWS_INTERNAL_IP_SUFFIXES)


def classify_event(
    *,
    event_id: str,
    event_name: str,
    event_source: str,
    region: str,
    time: datetime,
    source_ip: str,
    identity: str,
    error_code: str | None,
    known_ips: Iterable[str],
    home_regions: Iterable[str],
) -> list[Flag]:
    """Return zero or more flags for one CloudTrail event."""
    flags: list[Flag] = []
    failed = bool(error_code)
    known = set(known_ips)
    homes = set(home_regions)
    suffix = f" (call failed: {error_code})" if failed else ""

    def add(category: str, severity: str, reason: str) -> None:
        flags.append(
            Flag(
                category=category,
                severity=severity,
                reason=reason + suffix,
                event_id=event_id,
                event_name=event_name,
                event_source=event_source,
                region=region,
                time=time,
                source_ip=source_ip,
                identity=identity,
                failed=failed,
            )
        )

    if event_source == "iam.amazonaws.com" and event_name in PERSISTENCE_EVENTS:
        add(
            CATEGORY_PERSISTENCE,
            "high",
            f"{event_name} gives the attacker a way back in that survives deleting the leaked key",
        )

    if event_source == "ec2.amazonaws.com" and event_name in CRYPTOMINING_EVENTS:
        if homes and region not in homes:
            add(
                CATEGORY_CRYPTOMINING,
                "high",
                f"{event_name} in {region}, a region this account does not normally use",
            )
        else:
            add(
                CATEGORY_CRYPTOMINING,
                "medium",
                f"{event_name} launched compute that may still be running",
            )

    if event_source in EMAIL_SOURCES:
        severity = "high" if event_name in EMAIL_HIGH_EVENTS else "medium"
        add(
            CATEGORY_EMAIL,
            severity,
            f"SES call {event_name}: possible spam or phishing sent from your account",
        )

    if event_source.startswith(LLM_SOURCE_PREFIX):
        severity = "high" if event_name.startswith(LLM_HIGH_EVENT_PREFIXES) else "medium"
        add(
            CATEGORY_LLM,
            severity,
            f"Bedrock call {event_name}: possible LLMjacking (model usage billed to you)",
        )

    if (
        event_name in DISCOVERY_EVENTS
        and not is_aws_internal_ip(source_ip)
        and source_ip not in known
    ):
        add(
            CATEGORY_DISCOVERY,
            "low",
            f"{event_name} from an IP you did not list as yours ({source_ip})",
        )

    return flags


def verdict_for(flags: Iterable[Flag], event_count: int, had_errors: bool = False) -> str:
    """suspicious / likely clean / inconclusive."""
    flags = list(flags)
    if any(f.severity in ("high", "medium") for f in flags):
        return "suspicious"
    if event_count == 0:
        return "inconclusive"
    if flags:
        # Only low-severity discovery flags. Could be the owner from a new IP.
        return "inconclusive"
    if had_errors:
        return "inconclusive"
    return "likely clean"
