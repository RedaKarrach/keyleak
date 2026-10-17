# Reproducing a real detection, safely

This walks through a controlled version of the real incident: a key is "leaked", an
attacker uses it to create a backdoor and launch compute, and keyleak finds all of it
from a separate identity. The attacker is played by
[Stratus Red Team](https://stratus-red-team.cloud/) from Datadog, which runs real
AWS API calls that mimic known attack techniques, and then cleans up after itself.

Nothing here publishes a key anywhere. The "leak" is you handing a key to Stratus on
your own machine. Do not put the key in a repository, a gist, or a chat to make the
demo "more realistic". Bots would find it before you finish reading this page.

## Before you start

- **Use a throwaway AWS account.** A fresh account in your Organization, or a
  personal account you can close afterwards. Stratus creates real IAM users, keys,
  and (for the EC2 technique) a VPC and instances. Do not run this in an account you
  care about.
- **Have two identities ready.**
  - *Responder*: your normal admin login for the throwaway account (SSO or an admin
    user). keyleak runs as this one.
  - *Victim*: an IAM user you will create below, whose key plays the leaked key.
- **Install the tools.** The AWS CLI, keyleak (`pipx install git+https://github.com/RedaKarrach/keyleak`), and Stratus
  (`brew install datadog/stratus-red-team/stratus-red-team`, or a release binary
  from https://github.com/DataDog/stratus-red-team/releases).
- **Expect a small bill.** Cents to a couple of dollars if you clean up the same
  day. The EC2 technique tries to launch instance types that most new accounts are
  not allowed to run, so those launches usually fail, which is fine: failed
  `RunInstances` calls still show up in CloudTrail and keyleak still flags them.

Times below are rough. CloudTrail event history lags by 5 to 15 minutes.

## 1. Create the victim user and its key (as the responder)

```bash
export AWS_PROFILE=throwaway-admin
aws iam create-user --user-name leaked-dev
aws iam attach-user-policy --user-name leaked-dev \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name leaked-dev
```

Keep the `AccessKeyId` and `SecretAccessKey` from the last command in your terminal.
The `AccessKeyId` (`AKIA...`) is what you will hand to keyleak later. The attacker
having admin is realistic: most leaked keys belong to a developer with far too much
access.

## 2. Become the attacker

Open a second terminal. This one uses the leaked key and nothing else. Pick a region
you never use in this account, so the "unused region" detection has something to
bite on.

```bash
export AWS_ACCESS_KEY_ID=AKIA...            # leaked-dev's key
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=ap-southeast-1
unset AWS_PROFILE AWS_SESSION_TOKEN
aws sts get-caller-identity                 # discovery: the first thing every attacker does
aws iam list-users
```

Now run the Stratus techniques. Each one has a warm-up (sets up prerequisites with
Terraform) and a detonation (the actual attack call).

**Backdoor an existing user with a second access key.** The warm-up creates an IAM
user; the detonation adds an access key to it. This is the "new key on an old user"
pattern that gets missed most often.

```bash
stratus detonate aws.persistence.iam-backdoor-user
```

**Create a brand new admin user.** Creates a user, attaches `AdministratorAccess`,
and creates an access key and console password for it.

```bash
stratus detonate aws.persistence.iam-create-admin-user
```

**Launch unusual instances.** Tries to launch several large instances. In most
accounts the vCPU limit blocks it, so expect `RunInstances` errors in the Stratus
output. That is still an attacker fingerprint.

```bash
stratus detonate aws.execution.ec2-launch-unusual-instances
```

Optional, to make the timeline busier:

```bash
stratus detonate aws.discovery.ec2-enumerate-from-instance
stratus detonate aws.persistence.iam-create-backdoor-role
```

Leave this terminal open. You will use it for cleanup.

## 3. Wait, then investigate (as the responder)

Back in the first terminal, after 10 to 15 minutes:

```bash
export AWS_PROFILE=throwaway-admin
keyleak investigate AKIA... --home-region eu-west-1 --known-ip $(curl -s https://checkip.amazonaws.com)
```

Replace `eu-west-1` with whatever region you consider "home". `--known-ip` is your
public IP, so your own setup calls are not listed as discovery. Since the attacker
also ran from your machine, the attacker's calls come from that IP too; that is a
limitation of a single-machine demo, not of the tool. Leave the flag off if you want
to see the discovery flags.

What you should see:

- Verdict **SUSPICIOUS**.
- Under *Persistence*: `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`,
  `CreateLoginProfile` and, if you ran the role technique, `CreateRole`.
- Under *Cryptomining*: `RunInstances` in `ap-southeast-1`, marked
  "region not normally used", with "call failed" in the note if the launch was
  blocked.
- In *Identities investigated*: the leaked key first, then the users Stratus created
  (names like `malicious-iam-user` and the backdoored `stratus-red-team-...` user)
  and the keys it created for them, each with "How we got here" pointing at the
  event that created it. That is the pivot.
- Under *Next steps*: a `keyleak contain ... --confirm` line for every attacker
  created key, not just the leaked one.

If the verdict is inconclusive and the event count is zero, CloudTrail has not
caught up yet. Wait five more minutes and run it again.

## 4. Sweep, contain, report

```bash
keyleak sweep --since $(date -u +%Y-%m-%d)
```

You should see the Stratus users and keys as high concern. If any instance launch
succeeded, it shows up as a high-concern EC2 instance in `ap-southeast-1`.

```bash
keyleak contain AKIA... --confirm
```

Then, in the attacker terminal, confirm the leaked key is dead:

```bash
aws sts get-caller-identity
# An error occurred (InvalidClientTokenId) ...
```

And confirm the attacker's own key still works. This is the point of the exercise:

```bash
export AWS_ACCESS_KEY_ID=<key keyleak listed under the attacker-created user>
export AWS_SECRET_ACCESS_KEY=<its secret, from the Stratus output>
aws sts get-caller-identity
# Still works. Deactivating the leaked key did nothing about this one.
```

Finally:

```bash
keyleak report --out incident.html
```

Open it in a browser. The identities table, the flagged actions, the sweep results
and the support message are all there.

## 5. Clean up

Stratus removes what it created:

```bash
stratus cleanup --all
```

Then remove the victim user and anything Stratus could not clean (check the IAM
console for users or roles with `stratus` or `malicious` in the name):

```bash
export AWS_PROFILE=throwaway-admin
aws iam list-access-keys --user-name leaked-dev
aws iam delete-access-key --user-name leaked-dev --access-key-id AKIA...
aws iam detach-user-policy --user-name leaked-dev \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user --user-name leaked-dev
```

Run `keyleak sweep --since <today>` once more to confirm nothing is left, then close
the account if it was a one-off.

## A version without Stratus

If you do not want to install Stratus, the same signals can be produced by hand in
the attacker terminal. `--dry-run` on `run-instances` produces a `DryRunOperation`
error in CloudTrail, which keyleak flags as a failed `RunInstances`, and launches
nothing.

```bash
aws iam create-user --user-name backup-svc
aws iam create-access-key --user-name backup-svc
aws iam attach-user-policy --user-name backup-svc \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws ec2 run-instances --region ap-southeast-1 --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --instance-type g5.2xlarge --count 4 --dry-run
```

Clean up with `aws iam delete-access-key`, `detach-user-policy` and `delete-user`
for `backup-svc`, in that order.
