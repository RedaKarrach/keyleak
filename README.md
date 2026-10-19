<p align="center"><img src="docs/assets/logo-wordmark.svg" width="860" alt="keyleak: incident response for a leaked AWS key"></p>

# keyleak

What happens if your AWS key ends up on GitHub?

![keyleak in a terminal: investigate finds the attacker's user and key, sweep lists what is still running, contain switches the key off](docs/assets/demo.gif)

Short version, with pictures and a thirty-second demo: **https://redakarrach.github.io/keyleak/**

Within minutes, usually. Bots watch every public commit for strings that look like
`AKIA...`. When one lands, they try it. If it works, they start spending your money:
GPU instances for mining, Bedrock calls for resold AI access, SES for spam. Then they
make themselves a way back in, so that deleting the key you leaked does not lock them
out.

Most people find out from a bill, or from an email. By then the question is not
"did something happen" but "what exactly happened, and what is still running". AWS
has the answer in CloudTrail, but reading it under stress, across every region, is
not fun.

keyleak reads your own AWS logs and tells you what the attacker did and what is
still running. It never touches the stolen key. It runs with your own, separate
credentials and only uses the leaked key ID as a search term.

## Is this you?

- You got a surprise AWS bill, or a budget alert you did not expect.
- GitHub emailed you that a secret was found in one of your repositories.
- AWS emailed you about a "compromised" or "quarantined" access key, or applied the
  `AWSCompromisedKeyQuarantineV3` policy to a user.
- You just realised a key is in a public repo, and nothing has happened yet. Good.
  Run this anyway, then deactivate the key.

## What it does

- `keyleak investigate <KEY>` pulls every CloudTrail event for the key, across all
  regions, and sorts the attacker's actions into categories (persistence, mining,
  email abuse, LLM abuse, discovery).
- It then follows the trail: every user or key the attacker created is investigated
  too, automatically.
- `keyleak sweep` lists what is still running and still billing: EC2 instances,
  Lambda functions, and IAM users or keys created after the leak.
- `keyleak report` writes a single HTML file with the timeline, the resources, what
  you did about it, and a pre-filled message to AWS Support asking for a billing
  adjustment.

Everything above is read-only. The only command that changes your account is
`keyleak contain`, and it refuses to run without `--confirm`.

## The one thing most guides get wrong

Most advice stops at "delete the leaked key". That is necessary, but it is not
enough, and it is where people get burned twice.

The first thing a competent attacker does with a working key is make a new one.
They create an IAM user you have never heard of, or add a second access key to a
user you already have, or set a console password on an old service account. Those
survive the deletion of the leaked key. A week later the instances are back and so
is the bill.

keyleak treats every `CreateUser`, `CreateAccessKey`, `CreateLoginProfile` and
`AssumeRole` in the attacker's history as a new lead, and investigates that identity
the same way it investigated the leaked key. It keeps going until there are no new
leads, with a depth limit and a visited list so it cannot loop. The output tells you
which identities it found, how it found them, and what each one did. Delete all of
them, not just the first.

## Install

Python 3.11 or newer.

With [uv](https://docs.astral.sh/uv/):

```bash
uv tool install git+https://github.com/RedaKarrach/keyleak
```

Or try it once without installing anything:

```bash
uvx --from git+https://github.com/RedaKarrach/keyleak keyleak --help
```

With pipx, if that is what you already use:

```bash
pipx install git+https://github.com/RedaKarrach/keyleak
```

## Quickstart

You need credentials for an identity that is **not** the leaked key: your SSO login,
an admin user, or a user with the read-only policy in
[docs/keyleak-readonly-policy.json](docs/keyleak-readonly-policy.json). Put them in a
profile or in your environment the way you normally would.

```bash
export AWS_PROFILE=my-admin        # your OWN credentials, never the leaked key
```

Then, with the leaked key ID (the public half, `AKIA...`; never paste the secret):

```bash
keyleak investigate AKIAIOSFODNN7EXAMPLE --home-region eu-west-1
```

```bash
keyleak sweep --since 2026-10-14
```

```bash
keyleak contain AKIAIOSFODNN7EXAMPLE --confirm
```

```bash
keyleak report --out incident.html
```

That is the whole flow. `--home-region` is the region you normally work in; compute
launched anywhere else is treated as high severity. Pass `--known-ip` with your own
IP to stop your own activity from being listed as discovery.

## What the output looks like

`investigate`, on an account where the attacker created a user, gave it a key, and
launched instances in a region the owner never uses (details fabricated):

```text
┌──────────────────────── keyleak investigate ────────────────────────┐
│ Verdict: SUSPICIOUS                                                  │
│ Key: AKIAIOSFODNN7EXAMPLE  (IAM user "deploy-bot", Active, created   │
│ 2026-03-03 12:00:00Z)                                                │
│ Window: 2026-07-19 to 2026-10-17 UTC (90 days). CloudTrail event     │
│ history only covers the last 90 days.                                │
│ Regions queried: 17                                                  │
│ Events found: 6  Flagged: 5  Identities investigated: 3              │
└──────────────────────────────────────────────────────────────────────┘
                          Identities investigated

  #   Identity                                  How we got here                        Events   Flags   Verdict
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
  1   key AKIAIOSFODNN7EXAMPLE (user deploy-bot, Active)   the key you reported             5       4   SUSPICIOUS
  2   user backup-svc                           CreateUser by key AKIAIOSFODNN7EXAMPLE      1       1   SUSPICIOUS
                                                at 2026-10-14 12:02:00Z
  3   key AKIAATTACKER00000001 (user backup-svc, Active)   CreateAccessKey by key           1       1   SUSPICIOUS
                                                AKIAIOSFODNN7EXAMPLE at 2026-10-14 12:02:30Z

Flagged actions
Persistence (2)  new users, keys, passwords or policies. These survive deleting the leaked key.

  Sev    Time (UTC)             Event             Region      Source IP     Identity               Note
 ─────────────────────────────────────────────────────────────────────────────────────────────────────
  high   2026-10-14 12:02:00Z   CreateUser        us-east-1   203.0.113.5   AKIAIOSFODNN7EXAMPLE
  high   2026-10-14 12:02:30Z   CreateAccessKey   us-east-1   203.0.113.5   AKIAIOSFODNN7EXAMPLE

Cryptomining (1)  compute launched. Instances keep billing until you terminate them.

  Sev    Time (UTC)             Event          Region           Source IP     Identity     Note
 ───────────────────────────────────────────────────────────────────────────────────────────────────
  high   2026-10-14 12:09:00Z   RunInstances   ap-southeast-1   203.0.113.5   backup-svc   region not normally used

Discovery (2)  recon from an IP you did not list as yours. Weak on its own, telling next to the rest.

  Sev   Time (UTC)             Event               Region      Source IP     Identity               Note
 ────────────────────────────────────────────────────────────────────────────────────────────────────────
  low   2026-10-14 12:00:00Z   GetCallerIdentity   us-east-1   203.0.113.5   AKIAIOSFODNN7EXAMPLE   unfamiliar IP
  low   2026-10-14 12:01:00Z   ListUsers           us-east-1   203.0.113.5   AKIAIOSFODNN7EXAMPLE   unfamiliar IP

Next steps
  keyleak sweep --since 2026-10-14            # what is still running
  keyleak contain AKIAIOSFODNN7EXAMPLE --confirm   # deactivate the leaked key
  keyleak contain AKIAATTACKER00000001 --confirm   # attacker-created key
  keyleak report --out incident.html        # HTML report + AWS Support message
```

Note the third row. `AKIAATTACKER00000001` is not the key that leaked. It is the key
the attacker made, and it is the one that launched the instances.

`sweep` afterwards:

```text
┌───────────────────── keyleak sweep (read-only) ─────────────────────┐
│ Since: 2026-10-14 12:00 UTC   Regions: 17                            │
│ Concern: high 5  medium 0  low 2                                     │
└──────────────────────────────────────────────────────────────────────┘

  Concern   Kind             Region           Resource               Created / launched     Detail
 ───────────────────────────────────────────────────────────────────────────────────────────────────────────
  high      EC2 instance     ap-southeast-1   i-000000000000009a1    2026-10-14 12:09:00Z   g5.2xlarge launched
                                                                                            after --since; GPU/large
                                                                                            type is the classic
                                                                                            mining profile
  high      EC2 instance     ap-southeast-1   i-000000000000009a2    2026-10-14 12:09:00Z   g5.2xlarge launched ...
  high      EC2 instance     ap-southeast-1   i-000000000000009a3    2026-10-14 12:09:00Z   g5.2xlarge launched ...
  high      IAM access key   global           AKIAATTACKER00000001   2026-10-14 12:02:30Z   Active key on a user
                                                                                            that was also created
                                                                                            after --since
  high      IAM user         global           backup-svc             2026-10-14 12:02:00Z   user created after
                                                                                            --since; attackers
                                                                                            create users as a backdoor
  low       Lambda function  us-east-1        thumbnailer            2026-05-02 09:12:00Z   python3.12, untouched
                                                                                            since before --since
  low       EC2 instance     us-east-1        i-0f1e2d3c4b5a69788    2026-03-21 12:00:00Z   t3.small launched before
                                                                                            --since; Name="web-prod"

Cleanup is manual on purpose. Terminate what you do not recognise in the console, then run:
  keyleak report --out incident.html
```

`contain` prints exactly the one thing it changed:

```text
┌──────────────────────────── keyleak contain ────────────────────────────┐
│ Changed: access key AKIAIOSFODNN7EXAMPLE on IAM user deploy-bot          │
│   status Active -> Inactive                                              │
│   via iam:UpdateAccessKey (Status=Inactive) at 2026-10-17 12:48:28Z      │
│ Verified: IAM now reports the key as Inactive.                           │
│ Nothing else was touched. The key still exists so CloudTrail lookups     │
│ keep working.                                                            │
└──────────────────────────────────────────────────────────────────────────┘
Remember: deactivating this key does NOT remove users or keys the attacker created.
```

## What it can't do

- **It only sees 90 days.** CloudTrail's event history, which is what keyleak reads,
  keeps 90 days and nothing more. If the leak is older than that, the early part of
  the story is gone unless you had a trail writing to S3 (keyleak does not read
  those).
- **It needs your read access.** If your identity cannot call `cloudtrail:LookupEvents`
  in a region, that region is skipped and the output says so. If IAM reads are
  blocked, you still get the timeline but not the key's owner.
- **It is not a forensic suite.** It checks EC2, Lambda and IAM. Attackers also use
  ECS, SageMaker, Lightsail, Bedrock and SES. Look at the Billing console by service
  after you have dealt with what keyleak found.
- **It does not clean up for you.** Deleting users, terminating instances and
  removing roles are deliberate, manual steps. keyleak tells you what to look at and
  records what you did in the report.
- **Verdicts are heuristics.** "Suspicious" means it saw actions attackers take.
  "Likely clean" means it saw activity and none of it matched. "Inconclusive" means
  it did not see enough, or some lookups failed.

## How to use this safely

- **Never run keyleak with the leaked key.** Use a different identity: your SSO
  login, an admin user, or a user with the read-only policy. keyleak checks the
  credentials it is about to use and refuses to start if they are the leaked key.
- **It is read-only by default.** `investigate`, `sweep` and `report` make no
  changes. `contain` makes one change (sets one key to Inactive) and only with
  `--confirm`. It never deletes anything.
- **Least privilege.** [docs/keyleak-readonly-policy.json](docs/keyleak-readonly-policy.json)
  is the full set of permissions the read-only commands need:
  `cloudtrail:LookupEvents`, `iam:Get*`, `iam:List*`, `ec2:Describe*`, `lambda:List*`
  and `sts:GetCallerIdentity`. `contain` additionally needs `iam:UpdateAccessKey`
  ([docs/keyleak-contain-policy.json](docs/keyleak-contain-policy.json)).
- **Nothing leaves your machine.** keyleak talks to AWS and writes two JSON files
  under `~/.keyleak` (set `KEYLEAK_HOME` to move them) so `report` can find the last
  run. No telemetry, no third-party services.
- **Key IDs are not secrets.** The `AKIA...` string is the public half. Never pass the
  secret to keyleak; it has no use for it.

## Command reference

| Command | Changes anything? | What it does |
| --- | --- | --- |
| `keyleak investigate <KEY>` | No | CloudTrail timeline, flags, and the pivot to attacker-created identities. `--days`, `--regions`, `--max-depth`, `--no-pivot`, `--known-ip`, `--home-region`, `--json`. |
| `keyleak sweep` | No | Running EC2 and Lambda in every region, IAM users and keys created after `--since`. `--regions`, `--json`. |
| `keyleak contain <KEY> --confirm` | Yes, one key | Sets the key to Inactive with `iam:UpdateAccessKey`. Refuses without `--confirm`. |
| `keyleak report --out incident.html` | No | HTML report from the last runs, with an AWS Support message. |

Global options: `--profile` (your own credentials), `--region`, `--debug`.

CloudTrail limits `LookupEvents` to about two calls per second per region. keyleak
backs off and retries when throttled, so a big account with many regions can take a
few minutes. Pass `--regions eu-west-1,us-east-1` to go faster if you know where to
look. IAM and STS events are global and show up in `us-east-1`, so keep that region
in the list.

## Reproducing a detection safely

[docs/DEMO.md](docs/DEMO.md) walks through simulating an attacker with Stratus Red
Team in a throwaway account and running keyleak against the result.

## Development

```bash
uv sync --extra dev
```

```bash
uv run pytest
```

`uv.lock` pins the exact version of every dependency, and CI installs from it with
`uv sync --locked`, so a test run on your machine and in CI use the same packages.

The tests use botocore's `Stubber`; no AWS account or network is needed. The
attacker scenario in `tests/conftest.py` is the one described above, and
`tests/test_investigate.py` asserts both that it is flagged and that keyleak pivots
to the attacker's new key.

## License

MIT. See [LICENSE](LICENSE).
