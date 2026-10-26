# Optional AWS single-host demonstration

This is an optional route around unavailable local Docker virtualization. The
ordinary app and IP snapshot path do not need AWS. The public templates create
no resource unless explicitly run with `--apply`; no credentials, account IDs,
SSH keys, private IPs, licensed bundles or raw feeds are included.

The 2026-10-25 demonstration used the official Zetaris Docker bundle on one
Ubuntu 24.04 amd64 `m7i-flex.large` in Sydney, with SSH-only access and localhost
service bindings. This is a modest demonstration host (2 vCPU, 8 GiB), below the
bundle's four-CPU recommendation, not a production sizing claim. The default
bundle memory settings need the documented reductions below.

## Cost envelope, checked 2026-10-25

| Component | Sydney rate used | 48-hour estimate |
| --- | ---: | ---: |
| Linux m7i-flex.large | USD 0.1197/hour | USD 5.7456 |
| 30 GiB gp3, base IOPS/throughput | USD 0.096/GiB-month, 720-hour estimate | USD 0.1920 |
| One automatic public IPv4 | USD 0.005/hour | USD 0.2400 |
| Total | Before tax, transfers, credits and unrelated usage | **USD 6.1776** |

Rates came from the official [EC2 price data](https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps/ec2/USD/current/ec2.json),
[EBS price data](https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps/ec2/USD/current/ebs.json)
and [VPC IPv4 pricing](https://aws.amazon.com/vpc/pricing/). Recheck current regional
prices before applying. A two-attempt envelope is USD 12.3552 plus USD 3 reserve
for tax/transfer/small delays: USD 15.3552 before already incurred costs. The
script rejects a projected total reaching USD 20 and requires reviewed prior
costs. The reserve may be insufficient for unusual transfers/tax/other usage;
keep downloads local to the host and inspect account charges.

**This is a planning guard, not an AWS hard spending cap.** Budget alerts do not
stop billing. Independent AWS expiry plus an OS timer reduce unattended risk;
verify actual termination and volume removal. Do not leave stopped instances,
extra disks, snapshots, NAT gateways, load balancers or Elastic IPs behind.
This template creates none of the latter resources and does not upgrade plans.

[AWS Free Tier instance guidance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-free-tier-usage.html)
includes this candidate for the newer plan, but account restrictions/availability
can differ. The preflight checks `FreeTierEligible`, not a promise that all usage
is free. [Projects policies](https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html)
can restrict IAM/cross-account paths. The demonstrated single-host path avoids
external vendor AssumeRole and EKS/OIDC; if access is denied, stop and inspect.
A paid-plan upgrade is not an automatic remedy and is not part of this procedure.

## Read-only preflight in your own CloudShell

1. Sign into the intended account/project and select Sydney. Review its current
   charges/credits, service restrictions and cleanup responsibility.
2. Create a dedicated SSH key on your computer, e.g. `ssh-keygen -t ed25519 -f
   ./safeguard-demo`. Keep the private key local. Determine your workstation's
   current public IPv4; SSH must be restricted to that one address `/32`.
3. Upload only [launch_cloudshell.py](../deploy/aws/launch_cloudshell.py),
   [userdata-review.sh](../deploy/aws/userdata-review.sh) and the `.pub` file into
   one CloudShell directory. Do not upload the private key or provider tokens.
4. Review both scripts. Run with your actual reviewed public IP and key filename:

```bash
python3 launch_cloudshell.py --dry-run --with-scheduler \
  --source-cidr YOUR_PUBLIC_IPV4/32 --public-key safeguard-demo.pub
```

The plan reads your account, default VPC/public subnet, current official Canonical
Ubuntu AMI, instance characteristics and Scheduler availability. No VPC/network
is created. A custom subnet must already have an Internet Gateway route. The
script refuses an existing task instance or more than two recorded attempts.
An absent/default VPC or restricted service is a stop condition, not permission
to create a larger infrastructure stack. Preflight is not a CreateSchedule or
PassRole permission test.

## Explicit launch and expiry verification

After reviewing the plan and current prices, add the account ID printed by that
preflight and the actual prior cost (do not blindly use zero):

```bash
python3 launch_cloudshell.py --apply --with-scheduler \
  --account-id YOUR_REVIEWED_12_DIGIT_ACCOUNT \
  --source-cidr YOUR_PUBLIC_IPV4/32 --public-key safeguard-demo.pub \
  --prices-reviewed --existing-cost-usd YOUR_REVIEWED_PRIOR_COST
```

Override `--ec2-hourly-usd`, `--gp3-gib-monthly-usd` and `--ipv4-hourly-usd` when
current prices differ. Applying requires all review flags. It creates one EC2
instance, one SSH security group, one imported public key, and an expiry role
whose only action is terminating that exact instance. Its trust is restricted
to Scheduler, the same source account and the default schedule group. A one-off
UTC schedule automatically deletes itself after completion. IAM propagation
errors retry for at most two minutes without widening permissions; an unverified
schedule triggers termination of the newly created instance.

User-data arms a persistent absolute OS expiry before installing Docker. The
instance is configured for shutdown **termination**, encrypted 30 GiB root
storage with `DeleteOnTermination=true`, IMDSv2 and automatic public IPv4. A
restart cannot renew the deadline. The launch ledger is kept privately under
`~/.local/state/safeguard-zetaris-demo/launches.json`. Preserve it for cleanup;
never delete it merely to bypass the attempt guard.

Immediately verify in CloudShell/EC2: the one instance ID, schedule's exact
UTC deadline and target, shutdown behavior, root-disk deletion setting, and
instance health. After SSH login, check:

```bash
sudo cloud-init status --wait
sudo systemctl status safeguard-zetaris-expiry.timer --no-pager
sudo systemctl list-timers safeguard-zetaris-expiry.timer --no-pager
sudo docker version
sudo docker compose version
```

Verify the SSH host fingerprint against trusted instance console output before
accepting the host key. Do not disable host-key checking. Open no service ports
in the security group; only port 22 from the workstation `/32` is needed.

Official contracts: [Scheduler trust restrictions](https://docs.aws.amazon.com/scheduler/latest/UserGuide/cross-service-confused-deputy-prevention.html),
[universal AWS API targets](https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-universal.html),
[instance shutdown behavior](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_ChangingInstanceInitiatedShutdownBehavior.html),
[official Ubuntu AMIs](https://ubuntu.com/aws/docs/aws-how-to/instances/find-ubuntu-images/),
and [Docker Ubuntu installation](https://docs.docker.com/engine/install/ubuntu/).

## Install the separately licensed Zetaris bundle

Obtain your own bundle and registry credentials through Zetaris, accepting only
terms you are authorized to accept. Transfer the bundle by authenticated SCP;
keep it outside the SafeGuard repository. Do not put credentials into EC2
user-data, public archives or shell command arguments. Registry login should
use Docker's interactive password prompt or private `--password-stdin`.

The public [fresh-bundle helper](../deploy/zetaris/configure_fresh_bundle.py)
reproduces the non-secret settings and corrected password generation used in the
live setup. It defaults to a plan and refuses existing Zetaris containers or
volumes when applying. It is **only for first initialization**, never a password
reset or migration tool. Upload/extract the full SafeGuard source tree and retain
the helper at `safeguard-ai/deploy/zetaris/configure_fresh_bundle.py`. It derives
the repository root from this location; do not copy the helper out on its own.
From the parent directory containing the source tree and separate bundle, use a
private directory outside both:

```bash
python3 safeguard-ai/deploy/zetaris/configure_fresh_bundle.py --bundle ./zetaris-platform --private-dir ./private
python3 safeguard-ai/deploy/zetaris/configure_fresh_bundle.py --bundle ./zetaris-platform --private-dir ./private \
  --apply --fresh-install-confirmed
```

It creates separate random administrator/database passwords, including the
vendor-required letter/digit/allowed-special mix. No password is printed; private
`runtime-auth.json` and bundle `.env` are mode 600. Read them only through a
private local editor or protected transfer, not a shared log. On Windows apply
appropriate local file permissions yourself; the demonstrated helper runs on
Linux. It preserves image/version settings and configures loopback UI3000,
Spark `local[2]`/2g/two cores, API maximum heap1g, and no public TLS profile.
Driver/API/database ports in the reviewed bundle were already loopback-bound.
Review a changed bundle's Compose contract before adapting the helper.

From the bundle directory, log into the registry using your own credentials,
then run its official checks/startup:

```bash
./preflight.sh
sudo docker compose pull
sudo docker compose up -d
./verify.sh
sudo docker compose ps
sudo ss -lntp
```

Use the same Docker user/context for registry login, preflight and Compose (for
example all under a private `sudo -i` shell). Do not mix root's registry login
with a different user's Docker client. `init` and `bootstrap` exit0 is expected;
Postgres/driver/API/UI should be healthy. No database, application or Redis port may bind to 0.0.0.0 or `[::]`.
Do not enable the optional public Caddy/TLS profile in this tunnel-only setup.
Do not print `docker compose config` or `.env` into public logs: resolved values
include secrets. If startup fails, inspect privately and clean up this one
instance rather than silently creating another.

From your computer, keep an SSH tunnel open (replace host/key placeholders):

```bash
ssh -N -i ./safeguard-demo -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:3000:127.0.0.1:3000 \
  -L 127.0.0.1:8888:127.0.0.1:8888 ubuntu@YOUR_INSTANCE_PUBLIC_IP
```

Open localhost3000, log in privately and run `SELECT 1`. Transfer the public
`deploy/zetaris/domain_evidence.csv` to the host. From its bundle directory:

```bash
sudo docker compose exec -T driver bash -lc \
  'mkdir -p /home/zetaris/customer-data/shared/safeguard && cat > /home/zetaris/customer-data/shared/safeguard/domain_evidence.csv' < /path/to/domain_evidence.csv
```

Use the UI SQL Editor with [register_demo.sql](../deploy/zetaris/register_demo.sql).
Create only missing objects; preserve existing datasets. Follow
[Optional services](OPTIONAL_SERVICES.md) to connect the adapter, test actual rows
and empty lookups, and inspect query-cache closure. Redis/BlackIPS are not needed
for this database demo; the local snapshot is the simpler public path.

## Stop and clean up

Export any wanted private results before expiry. For this disposable demonstration,
the deadline terminates the instance and deletes its root volume. Stopping alone
can retain EBS charges. Use the recorded ID for early cleanup:

```bash
python3 launch_cloudshell.py --cleanup YOUR_RECORDED_INSTANCE_ID
```

The command verifies account, ledger and task tag, terminates that one instance,
checks its volumes are gone, then removes its security group, public-key metadata,
schedule and expiry role/policy. It refuses unrelated resources. If an automatic
termination happened long ago and EC2 no longer returns the instance, inspect the
ledger and console resources manually; do not broaden deletion filters. Confirm
zero remaining task instances/volumes/addresses/schedules and recheck billing.
Roles/security groups themselves do not stop an orphaned disk charge.

The public sanitized templates have local safety/contract tests; they have not
been applied as a second public-template cloud deployment. Their underlying
single-host procedure was actually run on 2026-10-25. Run local template checks:
`python -m unittest discover -s deploy -p test_deployment.py -v`. No AWS/Docker
requests are made by those tests. Licensing, account permissions and a new live
acceptance remain deployment-specific.
