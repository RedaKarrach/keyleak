"""Terminal rendering with rich. No AWS calls in here."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .contain import ContainResult
from .investigate import Investigation
from .rules import (
    CATEGORY_CRYPTOMINING,
    CATEGORY_DISCOVERY,
    CATEGORY_EMAIL,
    CATEGORY_LLM,
    CATEGORY_ORDER,
    CATEGORY_PERSISTENCE,
    Flag,
)
from .sweep import SweepResult

VERDICT_STYLE = {
    "suspicious": "bold red",
    "likely clean": "bold green",
    "inconclusive": "bold yellow",
}
SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan"}
CONCERN_STYLE = SEVERITY_STYLE


def fmt_time(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S") + "Z"


def short(text: str, width: int = 44) -> str:
    text = text or ""
    return text if len(text) <= width else text[: width - 1] + "…"


def compact_user_agent(ua: str) -> str:
    """'aws-cli/2.15.30 Python/3.11.6 Linux/... command/iam.create-user' -> 'aws-cli/2.15.30 command/iam.create-user'.

    The tool name and the command are what tell you who was at the keyboard. The
    full strings are in the User agents table.
    """
    if not ua:
        return "-"
    tokens = ua.split()
    keep = [tokens[0]] + [t.split("/", 1)[1] for t in tokens[1:] if t.startswith(("command/", "exec-env/"))]
    return " ".join(keep)


def _verdict_text(verdict: str) -> Text:
    return Text(verdict.upper(), style=VERDICT_STYLE.get(verdict, "bold"))


CATEGORY_EXPLANATION = {
    CATEGORY_PERSISTENCE: "new users, keys, passwords or policies. These survive deleting the leaked key.",
    CATEGORY_CRYPTOMINING: "compute launched. Instances keep billing until you terminate them.",
    CATEGORY_LLM: "Bedrock model calls billed to you (LLMjacking).",
    CATEGORY_EMAIL: "SES calls. Spam or phishing may have gone out from your account.",
    CATEGORY_DISCOVERY: "recon from an IP you did not list as yours. Weak on its own, telling next to the rest.",
}


def flag_note(flag: Flag) -> str:
    """Short per-row note; the category explanation carries the rest."""
    if flag.failed:
        return flag.reason.split("(call failed: ", 1)[-1].rstrip(")").join(["call failed: ", ""])
    if flag.category == CATEGORY_CRYPTOMINING and flag.severity == "high":
        return "region not normally used"
    if flag.event_name == "CreateLoginProfile":
        return "console password set"
    if flag.category == CATEGORY_DISCOVERY:
        return "unfamiliar IP"
    return ""


def print_investigation(console: Console, inv: Investigation, *, max_timeline: int = 200) -> None:
    root = inv.root_report
    header = Text()
    header.append("Verdict: ")
    header.append_text(_verdict_text(inv.verdict))
    header.append(f"\nKey: {inv.root.value}")
    if root and root.user_name:
        bits = [f'IAM user "{root.user_name}"']
        if root.key_status:
            bits.append(root.key_status)
        if root.key_created:
            bits.append(f"created {fmt_time(root.key_created)}")
        header.append("  (" + ", ".join(bits) + ")")
    if root and root.iam_note:
        header.append(f"\n{root.iam_note}", style="yellow")
    header.append(
        f"\nWindow: {inv.window_start:%Y-%m-%d} to {inv.window_end:%Y-%m-%d} UTC "
        f"({inv.lookback_days} days). CloudTrail event history only covers the last 90 days."
    )
    total_errors = sum(len(r.region_errors) for r in inv.reports)
    header.append(f"\nRegions queried: {len(inv.regions)}")
    if total_errors:
        header.append(f"  ({total_errors} region lookups failed, see notes)", style="yellow")
    events = inv.all_events
    header.append(f"\nEvents found: {len(events)}  Flagged: {len(inv.all_flags)}  Identities investigated: {len(inv.reports)}")
    if inv.caller:
        header.append(f"\nRunning as: {inv.caller.get('Arn', '?')}", style="dim")
    console.print(Panel(header, title="keyleak investigate", border_style=VERDICT_STYLE.get(inv.verdict, "white").replace("bold ", "")))

    # Identities (the pivot in one table)
    ident = Table(title="Identities investigated", box=box.SIMPLE_HEAVY, show_lines=False)
    ident.add_column("#", justify="right", no_wrap=True)
    ident.add_column("Identity", no_wrap=True)
    ident.add_column("How we got here")
    ident.add_column("Events", justify="right", no_wrap=True)
    ident.add_column("Flags", justify="right", no_wrap=True)
    ident.add_column("Verdict", no_wrap=True)
    for i, report in enumerate(inv.reports, start=1):
        label = report.identity.label
        if report.identity.kind == "AccessKeyId" and report.user_name:
            label += f" (user {report.user_name}, {report.key_status or 'status unknown'})"
        ident.add_row(
            str(i),
            label,
            report.discovered_via,
            str(len(report.events)),
            str(len(report.flags)),
            _verdict_text(report.verdict),
        )
    console.print(ident)
    if inv.skipped_pivots:
        console.print("[yellow]Pivots NOT followed:[/yellow]")
        for item in inv.skipped_pivots:
            console.print(f"  - {item['identity']}: {item['reason']} (found via {item['found_via']})")

    # Flags grouped by category: one table per category, explanation as the title
    flags = inv.all_flags
    if flags:
        console.print(Text("Flagged actions", style="bold"))
        for category in CATEGORY_ORDER:
            group = [f for f in flags if f.category == category]
            if not group:
                continue
            worst = min(group, key=lambda f: ["high", "medium", "low"].index(f.severity)).severity
            title = Text()
            title.append(f"{category} ({len(group)})", style=SEVERITY_STYLE.get(worst, "bold"))
            title.append(f"  {CATEGORY_EXPLANATION.get(category, '')}", style="dim")
            table = Table(title=title, title_justify="left", box=box.SIMPLE_HEAVY)
            table.add_column("Sev", no_wrap=True)
            table.add_column("Time (UTC)", no_wrap=True)
            table.add_column("Event", no_wrap=True)
            table.add_column("Region", no_wrap=True)
            table.add_column("Source IP", no_wrap=True)
            table.add_column("Identity", no_wrap=True)
            table.add_column("Note")
            for flag in group:
                table.add_row(
                    Text(flag.severity, style=SEVERITY_STYLE.get(flag.severity, "")),
                    fmt_time(flag.time),
                    flag.event_name,
                    flag.region,
                    flag.source_ip,
                    flag.identity,
                    flag_note(flag),
                )
            console.print(table)
    else:
        console.print("[green]No flagged actions.[/green]")

    # IPs and user agents
    ips = inv.source_ips
    if ips:
        suspects = set(inv.suspect_ips)
        ip_table = Table(title="Source IPs", box=box.SIMPLE_HEAVY)
        ip_table.add_column("IP")
        ip_table.add_column("Events", justify="right")
        ip_table.add_column("On flagged actions")
        for ip, count in ips.most_common():
            ip_table.add_row(ip, str(count), Text("yes", style="bold red") if ip in suspects else "")
        console.print(ip_table)
    agents = inv.user_agents
    if agents:
        ua_table = Table(title="User agents", box=box.SIMPLE_HEAVY)
        ua_table.add_column("User agent")
        ua_table.add_column("Events", justify="right")
        for agent, count in agents.most_common(15):
            ua_table.add_row(short(agent, 80), str(count))
        console.print(ua_table)

    # Timeline
    if events:
        flagged_ids = {f.event_id for f in flags}
        timeline = Table(title=f"Timeline ({len(events)} events, oldest first)", box=box.SIMPLE_HEAVY)
        timeline.add_column("Time (UTC)", no_wrap=True, min_width=20)
        timeline.add_column("Event", no_wrap=True, overflow="ellipsis", max_width=28)
        timeline.add_column("Region", no_wrap=True, min_width=9)
        timeline.add_column("Source IP", no_wrap=True, min_width=11)
        timeline.add_column("User agent", overflow="ellipsis", max_width=42)
        timeline.add_column("Identity", no_wrap=True, min_width=20)
        for ev in events[:max_timeline]:
            flagged = ev.event_id in flagged_ids
            name = ev.name + (f" [{ev.error_code}]" if ev.error_code else "")
            timeline.add_row(
                fmt_time(ev.time),
                Text(("! " if flagged else "  ") + name, style="bold red" if flagged else ""),
                ev.region,
                ev.source_ip,
                compact_user_agent(ev.user_agent),
                ev.access_key_id or ev.username,
            )
        console.print(timeline)
        console.print("[dim]Events marked ! are in the flagged actions above. User agents are shortened; full strings are in the table above.[/dim]")
        if len(events) > max_timeline:
            console.print(f"[dim]... {len(events) - max_timeline} more events; use --json for everything.[/dim]")
    else:
        console.print("[yellow]No CloudTrail events found for this key in the window.[/yellow]")

    # Notes
    notes = list(inv.notes)
    for report in inv.reports:
        for region, err in report.region_errors.items():
            notes.append(f"{report.identity.label}: {region}: {short(err, 100)}")
        if report.iam_note and report is not root:
            notes.append(f"{report.identity.label}: {report.iam_note}")
    if notes:
        console.print("[bold]Notes[/bold]")
        for note in notes:
            console.print(f"  - {note}")

    # What next
    first = inv.first_flag_time
    since = f"--since {first:%Y-%m-%d}" if first else "--since <date of the leak>"
    console.print()
    console.print("[bold]Next steps[/bold]")
    console.print(f"  keyleak sweep {since}            # what is still running")
    console.print(f"  keyleak contain {inv.root.value} --confirm   # deactivate the leaked key")
    for report in inv.reports[1:]:
        if report.identity.kind == "AccessKeyId" and report.key_status != "Inactive":
            console.print(f"  keyleak contain {report.identity.value} --confirm   # attacker-created key")
    console.print("  keyleak report --out incident.html        # HTML report + AWS Support message")


def print_sweep(console: Console, result: SweepResult) -> None:
    counts = result.counts()
    header = Text()
    header.append(f"Since: {result.since:%Y-%m-%d %H:%M} UTC   Regions: {len(result.regions)}\n")
    header.append("Concern: ")
    header.append(f"high {counts['high']}", style="bold red")
    header.append("  ")
    header.append(f"medium {counts['medium']}", style="yellow")
    header.append("  ")
    header.append(f"low {counts['low']}", style="cyan")
    console.print(Panel(header, title="keyleak sweep (read-only)", border_style="blue"))

    resources = result.sorted_resources()
    if resources:
        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Concern", no_wrap=True)
        table.add_column("Kind", no_wrap=True)
        table.add_column("Region", no_wrap=True)
        table.add_column("Resource", no_wrap=True)
        table.add_column("Created / launched", no_wrap=True)
        table.add_column("Detail")
        for res in resources:
            table.add_row(
                Text(res.concern, style=CONCERN_STYLE.get(res.concern, "")),
                res.kind,
                res.region,
                res.resource_id,
                fmt_time(res.created),
                short(res.detail, 80),
            )
        console.print(table)
    else:
        console.print("[green]Nothing running in EC2 or Lambda, and no IAM users or keys created since the date given.[/green]")

    if result.errors:
        console.print("[yellow]Skipped (errors):[/yellow]")
        for label, err in result.errors.items():
            console.print(f"  - {label}: {short(err, 100)}")
    for note in result.notes:
        console.print(f"  - {note}")
    console.print()
    console.print("[bold]Cleanup is manual on purpose.[/bold] Terminate what you do not recognise in the console, then run:")
    console.print("  keyleak report --out incident.html")


def print_contain(console: Console, result: ContainResult) -> None:
    body = Text()
    if result.changed:
        body.append("Changed: ", style="bold")
        body.append(f"access key {result.access_key_id} on IAM user {result.user_name}\n")
        body.append(f"  status {result.previous_status} -> {result.new_status}\n")
        body.append(f"  via iam:UpdateAccessKey (Status=Inactive) at {fmt_time(result.at)}\n")
        if result.verified:
            body.append("Verified: IAM now reports the key as Inactive.\n", style="green")
        else:
            body.append("Could not verify the new status; check the IAM console.\n", style="yellow")
    else:
        body.append(f"No change: access key {result.access_key_id} on user {result.user_name} was already Inactive.\n")
    body.append("Nothing else was touched. The key still exists so CloudTrail lookups keep working.", style="dim")
    console.print(Panel(body, title="keyleak contain", border_style="red" if result.changed else "green"))
    console.print("Remember: deactivating this key does NOT remove users or keys the attacker created.")
    console.print("Run `keyleak investigate` and `keyleak sweep` if you have not already.")


def print_notes(console: Console, notes: Iterable[str]) -> None:
    for note in notes:
        console.print(f"  - {note}")
