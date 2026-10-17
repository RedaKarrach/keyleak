"""The keyleak command line.

SAFETY RULE, stated here because it is the thing people get wrong under pressure:
keyleak NEVER authenticates with the leaked key. It uses your own credentials
(AWS_PROFILE, environment variables, SSO, the normal boto3 chain) and takes the
leaked key ID only as an argument. investigate, sweep and report are read-only.
Only contain changes anything, and only with --confirm.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console
from rich.text import Text

from . import __version__, aws, state
from .aws import BotoClientFactory, ClientFactory
from .contain import contain as run_contain
from .errors import KeyleakError
from .investigate import DEFAULT_MAX_DEPTH, MAX_LOOKBACK_DAYS, Investigator
from .output import print_contain, print_investigation, print_sweep
from .report import write_report
from .sweep import Sweeper

SAFETY_NOTE = (
    "keyleak never uses the leaked key. It runs with YOUR OWN AWS credentials "
    "(AWS_PROFILE / environment / SSO) and takes the leaked key ID only as an argument."
)

_DEBUG = False


def make_factory(profile: str | None, region: str | None) -> ClientFactory:
    """Build the client factory. Tests replace this to inject stubbed clients."""
    return BotoClientFactory(profile=profile, region=region)


def _factory(ctx: click.Context) -> ClientFactory:
    obj = ctx.ensure_object(dict)
    if "factory" not in obj:
        obj["factory"] = make_factory(obj.get("profile"), obj.get("region"))
    return obj["factory"]


def _regions(value: str | None, factory: ClientFactory) -> list[str]:
    if value:
        regions = [r.strip() for r in value.split(",") if r.strip()]
        if regions:
            return regions
    return aws.list_regions(factory)


CONTEXT = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


@click.group(context_settings=CONTEXT)
@click.version_option(__version__, prog_name="keyleak")
@click.option(
    "--profile",
    envvar="AWS_PROFILE",
    help="AWS profile holding YOUR OWN credentials. Never the leaked key.",
)
@click.option("--region", help="Default region (used for global services and as the home region).")
@click.option("--debug", is_flag=True, help="Show full tracebacks instead of short messages.")
@click.pass_context
def cli(ctx: click.Context, profile: str | None, region: str | None, debug: bool) -> None:
    """Incident response for a leaked AWS access key.

    Answers "what did the attacker do, and what is still running" from your own
    CloudTrail logs. Read-only by default: investigate, sweep and report change
    nothing. Only `contain` makes a change, and only with --confirm.

    SAFETY: keyleak never authenticates with the leaked key. It uses your own
    credentials (the normal AWS credential chain) and takes the leaked key ID only
    as an argument. Run it as a separate admin or read-only identity.
    """
    global _DEBUG
    _DEBUG = debug
    ctx.ensure_object(dict)
    ctx.obj.update({"profile": profile, "region": region, "debug": debug})


@cli.command()
@click.argument("access_key_id")
@click.option(
    "--days",
    default=MAX_LOOKBACK_DAYS,
    show_default=True,
    type=click.IntRange(1, MAX_LOOKBACK_DAYS),
    help="How far back to look. CloudTrail event history keeps 90 days at most.",
)
@click.option("--regions", help="Comma-separated regions to query. Default: every enabled region.")
@click.option(
    "--max-depth",
    default=DEFAULT_MAX_DEPTH,
    show_default=True,
    type=click.IntRange(0, 10),
    help="How many hops to follow when the attacker creates new users or keys.",
)
@click.option("--no-pivot", is_flag=True, help="Do not investigate users/keys the attacker created.")
@click.option(
    "--known-ip",
    multiple=True,
    metavar="IP",
    help="An IP that is yours. Discovery calls from other IPs get flagged. Repeatable.",
)
@click.option(
    "--home-region",
    multiple=True,
    metavar="REGION",
    help="A region you normally use. RunInstances elsewhere is high severity. Repeatable. Default: your configured region.",
)
@click.option("--json", "as_json", is_flag=True, help="Print the full result as JSON instead of tables.")
@click.pass_context
def investigate(
    ctx: click.Context,
    access_key_id: str,
    days: int,
    regions: str | None,
    max_depth: int,
    no_pivot: bool,
    known_ip: tuple[str, ...],
    home_region: tuple[str, ...],
    as_json: bool,
) -> None:
    """What did the leaked key do? Read-only.

    ACCESS_KEY_ID is the leaked key (AKIA... or ASIA...). Only the ID, never the
    secret. keyleak looks it up in CloudTrail across all regions, flags attacker
    behaviour, and then investigates every user or key the attacker created.
    """
    console = Console(stderr=as_json)
    factory = _factory(ctx)
    key = aws.validate_access_key_id(access_key_id)
    aws.refuse_if_using_leaked_key(factory, key)
    region_list = _regions(regions, factory)
    homes = list(home_region) or [factory.default_region()]

    with console.status("Starting...") as status:
        investigator = Investigator(
            factory,
            regions=region_list,
            lookback_days=days,
            max_depth=max_depth,
            known_ips=list(known_ip),
            home_regions=homes,
            pivot=not no_pivot,
            sleep=time.sleep,
            progress=lambda msg: status.update(msg),
        )
        inv = investigator.run(key)
        status.update("Checking who keyleak is running as...")
        inv.caller = aws.caller_identity(factory)

    data = inv.to_dict()
    saved = state.save(state.INVESTIGATE_FILE, data)
    if as_json:
        click.echo(state.dumps(data))
    else:
        print_investigation(console, inv)
        console.print(f"[dim]Saved to {saved} for `keyleak report`.[/dim]")


@cli.command()
@click.option(
    "--since",
    type=click.DateTime(formats=["%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"]),
    help="Resources created after this UTC date are suspicious. Default: the first flagged event of the last investigate, else 30 days ago.",
)
@click.option("--regions", help="Comma-separated regions to check. Default: every enabled region.")
@click.option("--json", "as_json", is_flag=True, help="Print the full result as JSON instead of a table.")
@click.pass_context
def sweep(ctx: click.Context, since: datetime | None, regions: str | None, as_json: bool) -> None:
    """What is still running and costing money? Read-only.

    Lists running EC2 instances and Lambda functions in every region, plus IAM
    users and access keys created after --since, each with a concern level.
    """
    console = Console(stderr=as_json)
    factory = _factory(ctx)
    region_list = _regions(regions, factory)
    now = datetime.now(timezone.utc)
    if since is None:
        last = state.load(state.INVESTIGATE_FILE) or {}
        first_flag = last.get("first_flag_time")
        if first_flag:
            since_dt = datetime.fromisoformat(first_flag)
            console.print(f"[dim]--since not given; using first flagged event from the last investigate ({since_dt:%Y-%m-%d %H:%M} UTC).[/dim]")
        else:
            since_dt = now - timedelta(days=30)
            console.print("[dim]--since not given; using 30 days ago.[/dim]")
    else:
        since_dt = since.replace(tzinfo=timezone.utc) if since.tzinfo is None else since

    with console.status("Starting...") as status:
        result = Sweeper(
            factory,
            regions=region_list,
            since=since_dt,
            sleep=time.sleep,
            now=now,
            progress=lambda msg: status.update(f"Checking {msg}"),
        ).run()

    data = result.to_dict()
    saved = state.save(state.SWEEP_FILE, data)
    if as_json:
        click.echo(state.dumps(data))
    else:
        print_sweep(console, result)
        console.print(f"[dim]Saved to {saved} for `keyleak report`.[/dim]")


@cli.command()
@click.argument("access_key_id")
@click.option("--confirm", is_flag=True, help="Required. Without it, contain refuses to run.")
@click.pass_context
def contain(ctx: click.Context, access_key_id: str, confirm: bool) -> None:
    """Deactivate the leaked key. The ONLY command that changes anything.

    Sets the key to Inactive (not deleted) with iam:UpdateAccessKey and nothing
    else. Refuses to run without --confirm. It does not remove users or keys the
    attacker created; see `keyleak investigate` for those.
    """
    console = Console()
    factory = _factory(ctx)
    result = run_contain(factory, access_key_id, confirm=confirm, sleep=time.sleep)
    if result.changed:
        state.append_action(result.to_dict())
    print_contain(console, result)


@cli.command()
@click.option(
    "--out",
    default="incident.html",
    show_default=True,
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    help="Where to write the HTML report.",
)
def report(out: Path) -> None:
    """Write a self-contained HTML report from the last investigate / sweep run.

    Includes the timeline, flagged actions, resources still running, the
    remediation keyleak performed, and a ready-to-send AWS Support message
    asking for a billing adjustment. No AWS calls.
    """
    console = Console()
    path = write_report(out)
    console.print(f"Wrote {path.resolve()}")
    console.print("Open it in a browser. The AWS Support message is at the bottom; fill in the bracketed parts.")


def _print_error(message: str, *, style: str = "bold red") -> None:
    err = Console(stderr=True, highlight=False)
    text = Text("keyleak: ", style=style)
    text.append(message)
    err.print(text)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Turns every expected failure into one readable line."""
    try:
        cli.main(args=argv, prog_name="keyleak", standalone_mode=True)
    except KeyleakError as exc:
        _print_error(str(exc))
        sys.exit(exc.exit_code)
    except (ClientError, BotoCoreError) as exc:
        if _DEBUG:
            raise
        _print_error(aws.friendly_error(exc))
        sys.exit(2)
    except KeyboardInterrupt:
        _print_error("interrupted.", style="yellow")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - last line of defence against stack traces
        if _DEBUG:
            raise
        _print_error(f"unexpected error: {exc!r}. Re-run with --debug for the full traceback.")
        sys.exit(3)
    return 0


if __name__ == "__main__":  # pragma: no cover
    main()
