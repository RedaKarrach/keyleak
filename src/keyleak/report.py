"""keyleak report: a self-contained HTML file from the last investigate / sweep run.

No AWS calls. Reads the JSON that the other commands saved and renders it with
inline CSS so the file can be emailed or attached to a support case as is.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import state
from .errors import NothingToReport
from .rules import CATEGORY_ORDER

CSS = """
:root { color-scheme: light; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; padding: 24px; max-width: 1100px; margin: 0 auto; color: #1b1b1b; background: #fff; line-height: 1.45; }
h1 { font-size: 26px; margin: 0 0 4px 0; }
h2 { font-size: 19px; margin: 32px 0 8px 0; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
p.meta { color: #666; margin: 0 0 16px 0; font-size: 14px; }
.verdict { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 700; color: #fff; }
.verdict.suspicious { background: #b3261e; }
.verdict.likely-clean { background: #1e7b34; }
.verdict.inconclusive { background: #b26a00; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; margin: 8px 0 16px 0; }
th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f3f3f3; }
tr.flagged td { background: #fff4f2; }
td.sev-high, td.concern-high { color: #b3261e; font-weight: 700; }
td.sev-medium, td.concern-medium { color: #b26a00; font-weight: 600; }
td.sev-low, td.concern-low { color: #0b5a8a; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
pre { background: #f6f6f6; border: 1px solid #ddd; padding: 12px; white-space: pre-wrap; word-break: break-word; }
textarea { width: 100%; min-height: 420px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; padding: 10px; box-sizing: border-box; }
ul { margin: 6px 0 12px 20px; }
.note { background: #fff8e1; border: 1px solid #f1d27a; padding: 10px 12px; border-radius: 4px; margin: 10px 0; }
.ok { background: #eef8ef; border: 1px solid #a9d8b0; padding: 10px 12px; border-radius: 4px; margin: 10px 0; }
.small { font-size: 12.5px; color: #555; }
"""


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def fmt_iso(value: str | None) -> str:
    if not value:
        return "-"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return esc(value)
    return parsed.strftime("%Y-%m-%d %H:%M:%S") + "Z"


def _date_only(value: str | None) -> str:
    return fmt_iso(value)[:10] if value else "an unknown date"


def _table(headers: list[str], rows: list[list[str]], row_classes: list[str] | None = None) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body_parts = []
    for i, row in enumerate(rows):
        cls = f' class="{row_classes[i]}"' if row_classes and row_classes[i] else ""
        body_parts.append(f"<tr{cls}>" + "".join(row) + "</tr>")
    body = "".join(body_parts)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def td(value: Any, cls: str | None = None) -> str:
    return f'<td class="{cls}">{esc(value)}</td>' if cls else f"<td>{esc(value)}</td>"


# -- sections ---------------------------------------------------------------------


def _summary_section(inv: dict[str, Any] | None, sweep: dict[str, Any] | None, actions: list[dict[str, Any]]) -> str:
    parts = []
    if inv:
        verdict = inv.get("verdict", "inconclusive")
        cls = verdict.replace(" ", "-")
        root = (inv.get("reports") or [{}])[0]
        owner = root.get("user_name")
        parts.append(f'<p>Verdict: <span class="verdict {esc(cls)}">{esc(verdict.upper())}</span></p>')
        parts.append(
            f"<p>Leaked key <code>{esc(inv['root']['value'])}</code>"
            + (f' belonged to IAM user <code>{esc(owner)}</code>' if owner else "")
            + (f" (status {esc(root.get('key_status'))})" if root.get("key_status") else "")
            + ".</p>"
        )
        parts.append(
            f"<p>CloudTrail window {fmt_iso(inv.get('window_start'))[:10]} to {fmt_iso(inv.get('window_end'))[:10]} UTC, "
            f"{len(inv.get('regions', []))} regions, {len(inv.get('timeline', []))} events, "
            f"{len(inv.get('flags', []))} flagged, {len(inv.get('reports', []))} identities investigated.</p>"
        )
        if inv.get("caller"):
            parts.append(f'<p class="small">Investigation run as {esc(inv["caller"].get("Arn", "?"))}.</p>')
        if root.get("iam_note"):
            parts.append(f'<div class="note">{esc(root["iam_note"])}</div>')
    else:
        parts.append('<div class="note">No investigation saved. Run <code>keyleak investigate &lt;KEY&gt;</code> first for a timeline.</div>')
    if sweep:
        counts = sweep.get("counts", {})
        parts.append(
            f"<p>Sweep on {fmt_iso(sweep.get('started_at'))}: {len(sweep.get('resources', []))} resources "
            f"({counts.get('high', 0)} high, {counts.get('medium', 0)} medium, {counts.get('low', 0)} low concern) "
            f"since {fmt_iso(sweep.get('since'))[:10]}.</p>"
        )
    else:
        parts.append('<div class="note">No sweep saved. Run <code>keyleak sweep</code> to list what is still running.</div>')
    if actions:
        parts.append(f"<p>{len(actions)} remediation action(s) recorded by keyleak contain.</p>")
    return "".join(parts)


def _identities_section(inv: dict[str, Any]) -> str:
    rows = []
    for i, rep in enumerate(inv.get("reports", []), start=1):
        ident = rep.get("identity", {})
        label = f"{'key' if ident.get('kind') == 'AccessKeyId' else 'user'} {ident.get('value')}"
        extra = ""
        if ident.get("kind") == "AccessKeyId" and rep.get("user_name"):
            extra = f" (user {rep['user_name']}, {rep.get('key_status') or 'status unknown'})"
        rows.append(
            [
                td(i),
                td(label + extra),
                td(rep.get("discovered_via")),
                td(len(rep.get("events", []))),
                td(len(rep.get("flags", []))),
                td(rep.get("verdict")),
            ]
        )
    out = _table(["#", "Identity", "How it was found", "Events", "Flags", "Verdict"], rows)
    skipped = inv.get("skipped_pivots") or []
    if skipped:
        items = "".join(f"<li>{esc(s.get('identity'))}: {esc(s.get('reason'))} (found via {esc(s.get('found_via'))})</li>" for s in skipped)
        out += f'<div class="note">Pivots not followed:<ul>{items}</ul></div>'
    return out


def _flags_section(inv: dict[str, Any]) -> str:
    flags = inv.get("flags") or []
    if not flags:
        return '<div class="ok">No flagged actions in the window.</div>'
    out = []
    for category in CATEGORY_ORDER:
        group = [f for f in flags if f.get("category") == category]
        if not group:
            continue
        rows = [
            [
                td(f.get("severity"), f"sev-{f.get('severity')}"),
                td(fmt_iso(f.get("time"))),
                td(f.get("event_name") + (" (failed)" if f.get("failed") else "")),
                td(f.get("region")),
                td(f.get("source_ip")),
                td(f.get("identity")),
                td(f.get("reason")),
            ]
            for f in group
        ]
        out.append(f"<h3>{esc(category)} ({len(group)})</h3>")
        out.append(_table(["Severity", "Time (UTC)", "Event", "Region", "Source IP", "Identity", "Why it matters"], rows))
    return "".join(out)


def _ips_section(inv: dict[str, Any]) -> str:
    ips = inv.get("source_ips") or {}
    suspects = set(inv.get("suspect_ips") or [])
    agents = inv.get("user_agents") or {}
    out = []
    if ips:
        rows = [
            [td(ip), td(count), td("yes" if ip in suspects else "")]
            for ip, count in sorted(ips.items(), key=lambda kv: -kv[1])
        ]
        out.append("<h3>Source IPs</h3>")
        out.append(_table(["IP", "Events", "On flagged actions"], rows))
    if agents:
        rows = [[td(ua), td(count)] for ua, count in sorted(agents.items(), key=lambda kv: -kv[1])[:20]]
        out.append("<h3>User agents</h3>")
        out.append(_table(["User agent", "Events"], rows))
    return "".join(out) or "<p>No source IPs recorded.</p>"


def _timeline_section(inv: dict[str, Any]) -> str:
    events = inv.get("timeline") or []
    if not events:
        return "<p>No events.</p>"
    flagged = {f.get("event_id") for f in inv.get("flags") or []}
    rows, classes = [], []
    for ev in events:
        name = ev.get("name", "") + (f" [{ev['error_code']}]" if ev.get("error_code") else "")
        rows.append(
            [
                td(fmt_iso(ev.get("time"))),
                td(name),
                td(ev.get("region")),
                td(ev.get("source_ip")),
                td(ev.get("user_agent")),
                td(ev.get("access_key_id") or ev.get("username")),
            ]
        )
        classes.append("flagged" if ev.get("event_id") in flagged else "")
    return _table(["Time (UTC)", "Event", "Region", "Source IP", "User agent", "Identity"], rows, classes)


def _sweep_section(sweep: dict[str, Any] | None) -> str:
    if not sweep:
        return "<p>No sweep saved.</p>"
    resources = sweep.get("resources") or []
    if not resources:
        out = '<div class="ok">Nothing running in EC2 or Lambda, and no IAM users or keys created since the date given.</div>'
    else:
        rows = [
            [
                td(r.get("concern"), f"concern-{r.get('concern')}"),
                td(r.get("kind")),
                td(r.get("region")),
                td(r.get("resource_id")),
                td(fmt_iso(r.get("created"))),
                td(r.get("detail")),
            ]
            for r in resources
        ]
        out = _table(["Concern", "Kind", "Region", "Resource", "Created / launched", "Detail"], rows)
    errors = sweep.get("errors") or {}
    if errors:
        items = "".join(f"<li>{esc(k)}: {esc(v)}</li>" for k, v in errors.items())
        out += f'<div class="note">Skipped because of errors:<ul>{items}</ul></div>'
    for note in sweep.get("notes") or []:
        out += f'<p class="small">{esc(note)}</p>'
    return out


def _actions_section(actions: list[dict[str, Any]]) -> str:
    if not actions:
        return (
            '<div class="note">keyleak has not recorded any remediation yet. '
            "<code>keyleak contain &lt;KEY&gt; --confirm</code> deactivates the leaked key and records it here. "
            "Anything you clean up by hand (terminated instances, deleted users) goes in the support message below.</div>"
        )
    rows = [
        [
            td(fmt_iso(a.get("at"))),
            td(a.get("action")),
            td(a.get("access_key_id")),
            td(a.get("user_name")),
            td(f"{a.get('previous_status')} -> {a.get('new_status')}"),
            td("yes" if a.get("verified") else "not verified"),
        ]
        for a in actions
    ]
    return _table(["Time (UTC)", "Action", "Key", "User", "Status", "Verified"], rows)


def _next_steps_section(inv: dict[str, Any] | None, sweep: dict[str, Any] | None) -> str:
    items = [
        "Remove the key from the public place it leaked to, and rotate any other secrets that were in the same file or commit.",
        "Deactivate the leaked key (<code>keyleak contain</code>) and, once nothing legitimate breaks, delete it in the IAM console.",
        "Delete every IAM user, access key, login profile and role the attacker created. They survive the leaked key.",
        "Terminate instances and delete functions you do not recognise, in every region, not just your usual one.",
        "Check the Billing console for services keyleak does not sweep (ECS, SageMaker, Lightsail, Bedrock, SES).",
        "Open an AWS Support case (Account and billing) and paste the message below.",
        "Turn on a CloudTrail trail to S3 so the next investigation is not limited to 90 days, and set a billing alarm.",
    ]
    if inv:
        for rep in inv.get("reports", [])[1:]:
            ident = rep.get("identity", {})
            if ident.get("kind") == "AccessKeyId" and rep.get("key_status") != "Inactive":
                items.insert(2, f"Attacker-created key <code>{esc(ident.get('value'))}</code> is {esc(rep.get('key_status') or 'of unknown status')}: deactivate it.")
            elif ident.get("kind") == "Username":
                items.insert(2, f"Attacker-created user <code>{esc(ident.get('value'))}</code>: delete it (keys, login profile, policies, then the user).")
    return "<ol>" + "".join(f"<li>{item}</li>" for item in items) + "</ol>"


def support_message(inv: dict[str, Any] | None, sweep: dict[str, Any] | None, actions: list[dict[str, Any]]) -> str:
    """Plain text the user can paste into an AWS Support case."""
    key = inv["root"]["value"] if inv else "<ACCESS KEY ID>"
    account = (inv or {}).get("caller", {}) or {}
    account_id = account.get("Account") or "<ACCOUNT ID>"
    first = (inv or {}).get("first_flag_time") or ((inv or {}).get("timeline") or [{}])[0].get("time") if inv else None
    when = _date_only(first) if first else "<DATE>"

    lines = [
        f"Subject: Billing adjustment request after unauthorized use of a compromised access key ({key})",
        "",
        "Hello AWS Support,",
        "",
        f"On or around {when} an IAM access key in my account ({account_id}) was accidentally exposed "
        "publicly and then used by a third party without my authorization. I am writing to request a "
        "review of the resulting charges and a billing adjustment for the usage I did not initiate.",
        "",
        "What happened, from CloudTrail event history (times in UTC):",
    ]
    flags = (inv or {}).get("flags") or []
    if flags:
        for f in flags[:40]:
            ip = f" from {f.get('source_ip')}" if f.get("source_ip") else ""
            lines.append(f"  - {fmt_iso(f.get('time'))}: {f.get('event_name')} in {f.get('region')}{ip} ({f.get('category')})")
        if len(flags) > 40:
            lines.append(f"  - ... and {len(flags) - 40} more flagged events (full list in the attached report)")
    else:
        lines.append("  - [paste the relevant events here]")
    ips = (inv or {}).get("suspect_ips") or []
    if ips:
        lines += ["", "Source IP addresses used by the unauthorized party: " + ", ".join(ips)]

    lines += ["", "Resources I found still running when I checked" + (f" ({fmt_iso(sweep.get('started_at'))})" if sweep else "") + ":"]
    resources = [r for r in ((sweep or {}).get("resources") or []) if r.get("concern") in ("high", "medium")]
    if resources:
        for r in resources[:40]:
            lines.append(f"  - {r.get('kind')} {r.get('resource_id')} in {r.get('region')}, created {fmt_iso(r.get('created'))}")
    else:
        lines.append("  - [list instances, functions, users and keys you had to remove]")

    lines += ["", "What I have done so far:"]
    if actions:
        for a in actions:
            lines.append(
                f"  - {fmt_iso(a.get('at'))}: deactivated access key {a.get('access_key_id')} on user "
                f"{a.get('user_name')} ({a.get('aws_call', 'iam:UpdateAccessKey Status=Inactive')})"
            )
    else:
        lines.append(f"  - [date]: deactivated access key {key}")
    lines += [
        "  - [date]: removed the exposed credential from the public location and rotated it",
        "  - [date]: deleted the IAM users and access keys created by the unauthorized party",
        "  - [date]: terminated the EC2 instances listed above",
        "",
        "I have reviewed the account for remaining unauthorized resources. Please let me know if you "
        "need any further details from CloudTrail or the billing console.",
        "",
        "Thank you,",
        "[your name]",
    ]
    return "\n".join(lines)


def build_html(
    inv: dict[str, Any] | None,
    sweep: dict[str, Any] | None,
    actions: list[dict[str, Any]],
    *,
    generated_at: datetime | None = None,
) -> str:
    if inv is None and sweep is None:
        raise NothingToReport(
            "Nothing to report yet. Run `keyleak investigate <KEY>` and/or `keyleak sweep` first; "
            "report builds from the last run."
        )
    generated = (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S") + "Z"
    key = inv["root"]["value"] if inv else "(no investigation)"
    sections = [
        "<h1>AWS leaked key incident report</h1>",
        f'<p class="meta">Generated by keyleak on {esc(generated)}. Key: <code>{esc(key)}</code>. '
        "keyleak never used the leaked key; everything here was read with the account owner's own credentials.</p>",
        "<h2>Summary</h2>",
        _summary_section(inv, sweep, actions),
    ]
    if inv:
        sections += [
            "<h2>Identities investigated (the pivot)</h2>",
            "<p>Deleting the leaked key does not remove users or keys the attacker created. Each one below was investigated in turn.</p>",
            _identities_section(inv),
            "<h2>Flagged actions</h2>",
            _flags_section(inv),
            "<h2>Attacker IPs and user agents</h2>",
            _ips_section(inv),
            "<h2>Timeline</h2>",
            _timeline_section(inv),
        ]
        notes = inv.get("notes") or []
        if notes:
            sections.append('<div class="note"><ul>' + "".join(f"<li>{esc(n)}</li>" for n in notes) + "</ul></div>")
    sections += [
        "<h2>Resources still running</h2>",
        _sweep_section(sweep),
        "<h2>Remediation steps taken</h2>",
        _actions_section(actions),
        "<h2>Remaining steps</h2>",
        _next_steps_section(inv, sweep),
        "<h2>Message to AWS Support</h2>",
        "<p>Open a support case under Account and billing, pick Billing, and paste this. Fill in the bracketed parts.</p>",
        f"<textarea readonly>{esc(support_message(inv, sweep, actions))}</textarea>",
        "<h2>Limitations</h2>",
        "<ul>"
        "<li>CloudTrail event history only covers the last 90 days.</li>"
        "<li>Only EC2, Lambda and IAM were swept. Other services can also cost money.</li>"
        "<li>This is a first-response tool, not a full forensic investigation.</li>"
        "</ul>",
    ]
    body = "\n".join(sections)
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>keyleak incident report {esc(key)}</title><style>{CSS}</style></head>"
        f"<body>\n{body}\n</body></html>\n"
    )


def write_report(out: Path, *, generated_at: datetime | None = None) -> Path:
    inv = state.load(state.INVESTIGATE_FILE)
    sweep = state.load(state.SWEEP_FILE)
    actions = state.load_actions()
    html_text = build_html(inv, sweep, actions, generated_at=generated_at)
    out = Path(out)
    out.write_text(html_text, encoding="utf-8")
    return out
