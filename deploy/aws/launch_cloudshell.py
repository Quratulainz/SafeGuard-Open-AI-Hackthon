"""Optional single-host deployment: review in your own AWS CloudShell.

Defaults to read-only planning. --apply creates ONE ephemeral EC2 instance;
--cleanup terminates only a recorded instance with this task's matching tag.
--apply requires --with-scheduler: a role limited to terminating this instance.
No credentials, provider licence or platform images are created.
"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tempfile
from datetime import datetime, timedelta, timezone
import uuid

REGION = 'ap-southeast-2'
TASK = 'safeguard-zetaris-demo'
TYPE = 'm7i-flex.large'
STATE = Path.home() / '.local' / 'state' / TASK / 'launches.json'
TAGS = [{'Key': 'Task', 'Value': TASK}, {'Key': 'Name', 'Value': TASK}]


def aws(*args):
    env = dict(os.environ, AWS_PAGER='')
    process = subprocess.run(['aws', '--region', REGION, '--output', 'json', '--cli-binary-format', 'base64', *args],
                             capture_output=True, text=True, env=env, check=False)
    if process.returncode:
        raise RuntimeError(process.stderr.strip()[:1000] or 'AWS CLI request failed')
    return json.loads(process.stdout) if process.stdout.strip() else {}


def read_state():
    return json.loads(STATE.read_text()) if STATE.exists() else {'task': TASK, 'attempts': []}


def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(STATE)


def validate_public_key(raw):
    raw = raw.strip()
    parts = raw.split()
    if len(raw) > 8192 or len(parts) < 2 or parts[0] not in ('ssh-ed25519', 'ssh-rsa'):
        raise ValueError('Supply an OpenSSH PUBLIC .pub key only, never a private key.')
    decoded = base64.b64decode(parts[1], validate=True)
    if len(decoded) < 32 or 'PRIVATE' in raw:
        raise ValueError('Invalid public key.')
    return raw


def tagged_instance(instance_id):
    if not re.fullmatch(r'i-[a-f0-9]{8,17}', instance_id):
        raise ValueError('Invalid instance ID.')
    reservations = aws('ec2', 'describe-instances', '--instance-ids', instance_id)['Reservations']
    instance = reservations[0]['Instances'][0]
    if {x['Key']: x['Value'] for x in instance.get('Tags', [])}.get('Task') != TASK:
        raise ValueError('Refusing to change an instance without this task tag.')
    return instance


def create_schedule_with_retry(*arguments):
    """Retry only the two known assume-role validation messages, for <=120s."""
    deadline = time.monotonic() + 120
    while True:
        try:
            return aws('scheduler', 'create-schedule', *arguments)
        except RuntimeError as exc:
            message = str(exc).lower()
            pending = ('validationexception' in message and (
                'cannot be assumed' in message or
                ('execution role' in message and 'must allow' in message
                 and 'scheduler' in message and 'assume' in message)))
            remaining = deadline - time.monotonic()
            if not pending or remaining <= 0:
                raise
            time.sleep(min(10, remaining))


def arm_scheduler(record, state):
    """Separate opt-in: no access except termination of this exact instance."""
    account_id = record['account_id']
    instance_arn = f"arn:aws:ec2:{REGION}:{account_id}:instance/{record['instance_id']}"
    role_name = TASK + '-expiry-' + record['client_token'][:8]
    schedule_name = TASK + '-expiry-' + record['client_token'][:8]
    trust = {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'Service': 'scheduler.amazonaws.com'},
        'Action': 'sts:AssumeRole', 'Condition': {'StringEquals': {
            'aws:SourceAccount': account_id,
            'aws:SourceArn': f'arn:aws:scheduler:{REGION}:{account_id}:schedule-group/default'}}}]}
    permission = {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Action': 'ec2:TerminateInstances', 'Resource': instance_arn}]}
    role = aws('iam', 'create-role', '--role-name', role_name,
               '--assume-role-policy-document', json.dumps(trust), '--tags', json.dumps(TAGS))['Role']
    record['expiry_role'] = role_name
    save_state(state)
    aws('iam', 'put-role-policy', '--role-name', role_name,
        '--policy-name', 'TerminateOnlyThisInstance', '--policy-document', json.dumps(permission))
    record['expiry_policy'] = True
    save_state(state)
    target = {'Arn': 'arn:aws:scheduler:::aws-sdk:ec2:terminateInstances',
              'RoleArn': role['Arn'], 'Input': json.dumps({'InstanceIds': [record['instance_id']]}),
              'RetryPolicy': {'MaximumEventAgeInSeconds': 3600, 'MaximumRetryAttempts': 12}}
    create_schedule_with_retry('--name', schedule_name, '--group-name', 'default',
        '--client-token', record['client_token'], '--schedule-expression',
        'at(' + record['deadline_utc'] + ')', '--schedule-expression-timezone', 'UTC',
        '--flexible-time-window', '{"Mode":"OFF"}', '--action-after-completion', 'DELETE',
        '--state', 'ENABLED', '--target', json.dumps(target))
    record['expiry_schedule'] = schedule_name
    save_state(state)
    check = aws('scheduler', 'get-schedule', '--name', schedule_name, '--group-name', 'default')
    if (check.get('State') != 'ENABLED' or check.get('ActionAfterCompletion') != 'DELETE'
            or check.get('ScheduleExpression') != 'at(' + record['deadline_utc'] + ')'
            or json.loads(check['Target']['Input']).get('InstanceIds') != [record['instance_id']]):
        raise RuntimeError('Expiry schedule did not match the reviewed target/deadline.')


def cleanup(instance_id):
    state = read_state()
    records = [x for x in state['attempts'] if x.get('instance_id') == instance_id]
    if not records:
        raise ValueError('Instance is not in this script\'s local launch ledger; inspect it manually.')
    record = records[0]
    if aws('sts', 'get-caller-identity')['Account'] != record.get('account_id'):
        raise ValueError('CloudShell is in a different AWS account from this recorded launch.')
    instance = tagged_instance(instance_id)
    volumes = [x['Ebs']['VolumeId'] for x in instance.get('BlockDeviceMappings', []) if 'Ebs' in x]
    aws('ec2', 'terminate-instances', '--instance-ids', instance_id)
    aws('ec2', 'wait', 'instance-terminated', '--instance-ids', instance_id)
    # Do not delete unrelated or retained user volumes. Stop for review if any remain.
    if volumes:
        remaining = aws('ec2', 'describe-volumes', '--filters', 'Name=volume-id,Values=' + ','.join(volumes))['Volumes']
        if remaining:
            raise RuntimeError('Instance terminated; retained volumes require review: ' +
                               ', '.join(v['VolumeId'] for v in remaining))
    if record.get('group_id'):
        aws('ec2', 'delete-security-group', '--group-id', record['group_id'])
    if record.get('key_name'):
        aws('ec2', 'delete-key-pair', '--key-name', record['key_name'])
    if record.get('expiry_schedule'):
        try:
            aws('scheduler', 'delete-schedule', '--name', record['expiry_schedule'], '--group-name', 'default')
        except RuntimeError as exc:
            if 'ResourceNotFoundException' not in str(exc):
                raise
    if record.get('expiry_policy'):
        aws('iam', 'delete-role-policy', '--role-name', record['expiry_role'], '--policy-name', 'TerminateOnlyThisInstance')
    if record.get('expiry_role'):
        aws('iam', 'delete-role', '--role-name', record['expiry_role'])
    record['cleaned_at'] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    print('Recorded instance terminated, its volumes absent, and its SSH group/key metadata removed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account-id', help='Expected 12-digit AWS account ID from the intended project')
    parser.add_argument('--connection-config', type=Path,
                        default=Path(__file__).with_name('connection.json'),
                        help='Private-to-team JSON containing public_key and operator source_cidr')
    parser.add_argument('--source-cidr', help='Operator workstation public IPv4/32, not CloudShell IP')
    parser.add_argument('--public-key', type=Path, help='Uploaded public .pub file; private key stays local')
    parser.add_argument('--subnet-id', help='Existing public subnet; otherwise select from the default VPC')
    parser.add_argument('--ami-id', help='Canonical Ubuntu 24.04 LTS amd64; otherwise find latest official release')
    parser.add_argument('--apply', '--launch', dest='launch', action='store_true', help='Create resources; default is read-only plan')
    parser.add_argument('--dry-run', action='store_true', help='Explicit read-only preflight (also the default)')
    parser.add_argument('--with-scheduler', action='store_true',
                        help='Required for apply: 48h AWS deadline plus one exact-instance termination role')
    parser.add_argument('--cleanup', metavar='INSTANCE_ID', help='Terminate a recorded instance and remove its metadata')
    parser.add_argument('--existing-cost-usd', type=float, help='Already incurred costs you reviewed; required for apply')
    parser.add_argument('--prices-reviewed', action='store_true', help='Confirm current official regional prices have been checked')
    parser.add_argument('--ec2-hourly-usd', type=float, default=0.1197)
    parser.add_argument('--gp3-gib-monthly-usd', type=float, default=0.096)
    parser.add_argument('--ipv4-hourly-usd', type=float, default=0.005)
    args = parser.parse_args()
    if args.cleanup:
        if args.launch:
            parser.error('--launch and --cleanup are mutually exclusive')
        cleanup(args.cleanup)
        return
    if args.launch and args.dry_run:
        parser.error('--apply and --dry-run are mutually exclusive')
    rates = (args.ec2_hourly_usd, args.gp3_gib_monthly_usd, args.ipv4_hourly_usd)
    if any(not 0 < value < 100 for value in rates):
        parser.error('Supply finite positive regional prices below USD 100 per unit')
    if args.existing_cost_usd is not None and not 0 <= args.existing_cost_usd < 20:
        parser.error('Previously incurred costs must be known, nonnegative and below USD 20')
    single_48h = 48 * (args.ec2_hourly_usd + args.ipv4_hourly_usd) + 30 * args.gp3_gib_monthly_usd * 48 / 720
    two_attempts_with_reserve = 2 * single_48h + 3
    projected_total = two_attempts_with_reserve + (args.existing_cost_usd or 0)
    if projected_total >= 20:
        parser.error('Two full 48h attempts plus USD 3 reserve and reviewed prior cost would reach USD 20')
    if args.launch and (not args.with_scheduler or not args.prices_reviewed or args.existing_cost_usd is None):
        parser.error('--apply requires --with-scheduler, --prices-reviewed and --existing-cost-usd; no OS-only paid launch')
    connection = json.loads(args.connection_config.read_text(encoding='utf-8-sig')) if args.connection_config.exists() else {}
    args.source_cidr = args.source_cidr or connection.get('source_cidr')
    key_text = args.public_key.read_text() if args.public_key else connection.get('public_key', '')
    if not args.source_cidr or not key_text:
        parser.error('Provide connection.json or --source-cidr plus --public-key')
    if args.account_id and not re.fullmatch(r'[0-9]{12}', args.account_id):
        raise ValueError('Expected a 12-digit account ID.')
    if args.launch and not args.account_id:
        parser.error('--apply requires --account-id matching the reviewed preflight account')
    network = ipaddress.ip_network(args.source_cidr, strict=True)
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValueError('SSH source must be the operator\'s public IPv4 /32.')
    public_key = validate_public_key(key_text)
    userdata = Path(__file__).with_name('userdata-review.sh')
    if not userdata.is_file():
        raise ValueError('Keep the reviewed userdata-review.sh alongside this script.')
    account_id = aws('sts', 'get-caller-identity')['Account']
    if args.account_id and account_id != args.account_id:
        raise ValueError('CloudShell is not in the intended AWS account; no resources created.')
    state = read_state()
    if state.get('task') != TASK or len(state['attempts']) >= 2:
        raise ValueError('At most two attempts are budgeted. Review earlier charges before any further launch.')
    existing = aws('ec2', 'describe-instances', '--filters', 'Name=tag:Task,Values=' + TASK,
                   'Name=instance-state-name,Values=pending,running,stopping,stopped')['Reservations']
    if any(r.get('Instances') for r in existing):
        raise ValueError('An earlier task instance still exists. Inspect/clean it up before launching another.')
    if args.subnet_id:
        subnet = aws('ec2', 'describe-subnets', '--subnet-ids', args.subnet_id)['Subnets'][0]
    else:
        vpcs = aws('ec2', 'describe-vpcs', '--filters', 'Name=is-default,Values=true')['Vpcs']
        if len(vpcs) != 1:
            raise ValueError('No single default VPC found. Supply an existing approved public subnet; no VPC will be created.')
        subnets = aws('ec2', 'describe-subnets', '--filters', 'Name=vpc-id,Values=' + vpcs[0]['VpcId'],
                      'Name=default-for-az,Values=true', 'Name=state,Values=available')['Subnets']
        offerings = aws('ec2', 'describe-instance-type-offerings', '--location-type', 'availability-zone',
                       '--filters', 'Name=instance-type,Values=' + TYPE)['InstanceTypeOfferings']
        available_zones = {x['Location'] for x in offerings}
        candidates = sorted((s for s in subnets if s['AvailabilityZone'] in available_zones), key=lambda s: s['AvailabilityZone'])
        if not candidates:
            raise ValueError('No default subnet offers the reviewed instance type. No networking will be created.')
        subnet = candidates[0]
        args.subnet_id = subnet['SubnetId']
    if not subnet['AvailabilityZone'].startswith(REGION):
        raise ValueError('Subnet must be in Sydney.')
    tables = aws('ec2', 'describe-route-tables', '--filters', 'Name=association.subnet-id,Values=' + args.subnet_id)['RouteTables']
    if not tables:
        tables = aws('ec2', 'describe-route-tables', '--filters', 'Name=vpc-id,Values=' + subnet['VpcId'],
                     'Name=association.main,Values=true')['RouteTables']
    if not any(r.get('DestinationCidrBlock') == '0.0.0.0/0' and r.get('GatewayId', '').startswith('igw-')
               and r.get('State') == 'active' for t in tables for r in t.get('Routes', [])):
        raise ValueError('Subnet needs an active Internet Gateway route; this script creates no NAT/networking.')
    if args.ami_id:
        images = aws('ec2', 'describe-images', '--image-ids', args.ami_id)['Images']
    else:
        images = aws('ec2', 'describe-images', '--owners', '099720109477', '--filters',
                     'Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*',
                     'Name=state,Values=available', 'Name=architecture,Values=x86_64')['Images']
    if not images:
        raise ValueError('No current official Ubuntu 24.04 amd64 image found.')
    image = sorted(images, key=lambda x: x['CreationDate'])[-1]
    args.ami_id = image['ImageId']
    if (image.get('OwnerId') != '099720109477' or image.get('Architecture') != 'x86_64'
            or image.get('RootDeviceType') != 'ebs' or image.get('ProductCodes')
            or not re.fullmatch(r'ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24\.04-amd64-server-[0-9.]+', image.get('Name', ''))):
        raise ValueError('Expected a current official Canonical Ubuntu 24.04 amd64 EBS image, without product charges.')
    kind = aws('ec2', 'describe-instance-types', '--instance-types', TYPE)['InstanceTypes'][0]
    if kind['MemoryInfo']['SizeInMiB'] < 8192 or 'x86_64' not in kind['ProcessorInfo']['SupportedArchitectures']:
        raise ValueError('Instance characteristics differ from the reviewed 8 GiB x86-64 candidate.')
    if kind.get('FreeTierEligible') is not True:
        raise ValueError('The selected instance is not reported FreeTierEligible. Stop; do not upgrade or resize automatically.')
    ttl_hours = 48 if args.with_scheduler else 12
    if args.with_scheduler:
        # Read access is a useful availability check, not proof that CreateSchedule/PassRole is authorized.
        aws('scheduler', 'list-schedules', '--group-name', 'default', '--max-results', '1')
    print(json.dumps({'mode': 'APPLY' if args.launch else 'READ_ONLY_PREFLIGHT', 'region': REGION,
                      'account_id': account_id, 'free_tier_instance_reported': kind['FreeTierEligible'],
                      'instance_type': TYPE, 'subnet': args.subnet_id, 'ami': args.ami_id,
                      'ssh_source': str(network), 'root_volume': '30 GiB gp3; encrypted; delete on termination',
                      'expiry': f'{ttl_hours}h OS timer; shutdown TERMINATE; AWS Scheduler=' + str(args.with_scheduler),
                      'cost_48h_before_tax_transfer_usd': round(single_48h, 4),
                      'budget_two_attempts_plus_reserve_usd': round(two_attempts_with_reserve, 4),
                      'projected_with_prior_cost_usd': round(projected_total, 4),
                      'price_basis': 'Operator-reviewed input rates; defaults are Sydney estimates checked 2026-10-25',
                      'billing_cap': False,
                      'iam_resources': 'one role + one inline policy restricted to new instance' if args.with_scheduler else 0}, indent=2))
    if not args.launch:
        print('No resources created. This is read-only preflight, not an AWS permission or billing-cap guarantee.')
        print('Review account plan, existing charges and the independent cleanup check before --apply --account-id <reviewed-id>.')
        return
    client_token = str(uuid.uuid4())
    suffix = client_token[:8]
    record = {'client_token': client_token, 'account_id': args.account_id,
              'started_at': datetime.now(timezone.utc).isoformat(),
              'deadline_utc': (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).strftime('%Y-%m-%dT%H:%M:%S'),
              'ttl_hours': ttl_hours,
              'key_name': TASK + '-' + suffix, 'group_name': TASK + '-' + suffix}
    state['attempts'].append(record)
    save_state(state)
    try:
        aws('ec2', 'import-key-pair', '--key-name', record['key_name'],
            '--public-key-material', base64.b64encode(public_key.encode()).decode(),
            '--tag-specifications', json.dumps([{'ResourceType': 'key-pair', 'Tags': TAGS}]))
        record['key_imported'] = True
        save_state(state)
        group = aws('ec2', 'create-security-group', '--group-name', record['group_name'],
                    '--description', 'Temporary Zetaris: SSH from operator only; all services tunnelled',
                    '--vpc-id', subnet['VpcId'],
                    '--tag-specifications', json.dumps([{'ResourceType': 'security-group', 'Tags': TAGS}]))
        record['group_id'] = group['GroupId']
        save_state(state)
        aws('ec2', 'authorize-security-group-ingress', '--group-id', record['group_id'],
            '--ip-permissions', json.dumps([{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                                            'IpRanges': [{'CidrIp': str(network), 'Description': 'Operator SSH only'}]}]))
        # Pass an exact UTC deadline; restarting the instance cannot extend it.
        rendered_userdata = userdata.read_text().replace("date -u -d '+48 hours' +%s",
                                                        "date -u -d '" + record['deadline_utc'] + "Z' +%s")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as staging:
            staging.write(rendered_userdata)
            staged_userdata = Path(staging.name)
        try:
            response = aws('ec2', 'run-instances', '--image-id', args.ami_id, '--instance-type', TYPE,
                       '--count', '1', '--key-name', record['key_name'], '--client-token', client_token,
                       '--instance-initiated-shutdown-behavior', 'terminate',
                       '--metadata-options', 'HttpTokens=required,HttpEndpoint=enabled,HttpPutResponseHopLimit=1',
                       '--block-device-mappings', json.dumps([{'DeviceName': image['RootDeviceName'], 'Ebs': {
                           'VolumeSize': 30, 'VolumeType': 'gp3', 'Iops': 3000, 'Throughput': 125,
                           'Encrypted': True, 'DeleteOnTermination': True}}]),
                       '--network-interfaces', json.dumps([{'DeviceIndex': 0, 'SubnetId': args.subnet_id,
                           'Groups': [record['group_id']], 'AssociatePublicIpAddress': True, 'DeleteOnTermination': True}]),
                       '--tag-specifications', json.dumps([{'ResourceType': t, 'Tags': TAGS} for t in ('instance', 'volume')]),
                       '--user-data', 'file://' + str(staged_userdata))
        finally:
            staged_userdata.unlink(missing_ok=True)
        record['instance_id'] = response['Instances'][0]['InstanceId']
        save_state(state)
        if args.with_scheduler:
            try:
                arm_scheduler(record, state)
            except Exception:
                # No unattended 48h VM without the approved independent guard.
                # Terminate just this new instance; preserve the ledger for cleanup.
                aws('ec2', 'terminate-instances', '--instance-ids', record['instance_id'])
                print('Scheduler could not be verified; new instance termination requested. Review ledger/cleanup; no plan upgrade.', file=sys.stderr)
                raise
    except Exception:
        # A timed-out launch can still have succeeded. Check the idempotency token
        # before reporting failure; never retry by creating another instance.
        found = aws('ec2', 'describe-instances', '--filters', 'Name=client-token,Values=' + client_token)['Reservations']
        instances = [i for r in found for i in r.get('Instances', [])]
        if instances:
            record['instance_id'] = instances[0]['InstanceId']
            save_state(state)
            print('Launch outcome needs inspection; recorded instance:', record['instance_id'], file=sys.stderr)
        else:
            if record.get('group_id'):
                aws('ec2', 'delete-security-group', '--group-id', record['group_id'])
            if record.get('key_imported'):
                aws('ec2', 'delete-key-pair', '--key-name', record['key_name'])
        raise
    print('Created one instance:', record['instance_id'])
    print('Absolute expiry UTC:', record['deadline_utc'])
    print('Immediately verify cloud-init, the expiry timer, terminate shutdown behavior and DeleteOnTermination.')
    print('If bootstrap fails, clean up this instance instead of silently starting another.')
    print('Cleanup: python3 launch_cloudshell.py --cleanup ' + record['instance_id'])


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, KeyError, IndexError, OSError, json.JSONDecodeError) as exc:
        print('Stopped:', str(exc), file=sys.stderr)
        sys.exit(1)
