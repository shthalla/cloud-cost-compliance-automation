# Cloud Cost & Compliance Scanner

[![CI](https://github.com/your-username/cloud-cost-compliance-automation/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/cloud-cost-compliance-automation/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Python/Boto3 automation that scans an AWS account for **idle and unused
resources** (EC2, EBS, Elastic IPs, Load Balancers, EBS snapshots), reports
the findings **on a schedule via Amazon SNS**, and pairs that with **AWS
Config custom rules** for ongoing compliance drift detection (unencrypted
volumes, open security groups, missing required tags).

Runs as a scheduled AWS Lambda function. Deployable with Terraform or
CloudFormation. Fully unit-tested with [moto](https://github.com/getmoto/moto)
— the test suite costs **$0** and needs **no AWS credentials** to run.

```
┌────────────────┐      ┌──────────────────┐      ┌─────────────────────┐
│  EventBridge    │ ───▶ │  Scanner Lambda   │ ───▶ │  SNS topic + S3      │
│  daily schedule │      │  5 scanners       │      │  notify + archive    │
└────────────────┘      └──────────────────┘      └─────────────────────┘

┌────────────────┐      ┌──────────────────┐      ┌─────────────────────┐
│  Resource       │ ───▶ │  AWS Config       │ ───▶ │  3 rule Lambdas      │
│  config change  │      │  custom rules     │      │  → compliance verdict│
└────────────────┘      └──────────────────┘      └─────────────────────┘
```

See [`docs/architecture.svg`](docs/architecture.svg) for the full diagram.

## What it finds

| Scanner | Flags | Severity logic |
|---|---|---|
| **Idle EC2** | Running instances with avg CPU below threshold over a lookback window | Scales with instance cost and how far below threshold |
| **Unattached EBS** | Volumes in `available` state past a grace period | Scales with age and size |
| **Unused Elastic IPs** | Allocated EIPs with no instance/ENI association | Flat MEDIUM |
| **Stale EBS snapshots** | Snapshots older than a configurable age | Lower severity if AMI-backed (so you don't accidentally suggest breaking an AMI) |
| **Idle Load Balancers** | ALB/NLB with near-zero requests/flows over a lookback window | Flat MEDIUM |

Every finding includes a **cost-estimate** (coarse, prioritization-only —
not a replacement for Cost Explorer) and a **severity** (LOW/MEDIUM/HIGH),
and resources tagged with an exclusion key (default: `doNotDelete`,
`scanner:ignore`) are always skipped.

## What it enforces continuously

| AWS Config rule | Checks |
|---|---|
| `ebs-encryption-enabled` | EBS volumes are encrypted |
| `restricted-security-group-ingress` | No security group allows unrestricted ingress (`0.0.0.0/0`/`::/0`) on sensitive ports (SSH, RDP, common DB ports — configurable), or all traffic from anywhere |
| `required-tags-present` | EC2 instances, EBS volumes, and load balancers carry your required tags (e.g. `Environment`, `Owner`, `CostCenter`) |

These run on every configuration change (not just on a schedule), so drift
is caught the moment it happens, not on the next scheduled scan.

## Sample output

A real run against a small test account produces something like this (full
file: [`docs/sample_sns_notification.txt`](docs/sample_sns_notification.txt),
generated directly from the formatter code — not hand-written):

```
Cloud Cost & Compliance Scan Report
========================================
Account: 123456789012
Scan window: 2026-06-24T08:00:01+00:00 -> 2026-06-24T08:00:47+00:00
Regions scanned: us-east-1, us-west-2
Total findings: 5
Estimated potential monthly savings: $114.88

--- EC2_INSTANCE (1 findings, ~$70.08/mo) ---
  [HIGH] i-0a1b2c3d4e5f6g7h8 (us-east-1) ~$70.08/mo -- Average CPU
  utilization 1.23% over 14 days (threshold: 5.0%)

--- EBS_VOLUME (1 findings, ~$20.00/mo) ---
  [HIGH] vol-0fedcba9876543210 (us-east-1) ~$20.00/mo -- Volume
  unattached for 46 days (grace period: 7 days), 250 GiB gp3
...
```

The full JSON report (archived to S3 on every run) looks like
[`docs/sample_report.json`](docs/sample_report.json).

## Repository layout

```
src/cloud_compliance_scanner/
├── config.py                  # env-var-driven configuration, all thresholds
├── models.py                  # Finding / ScanResult data model
├── orchestrator.py            # runs every scanner across every region
├── lambda_handler.py          # Lambda entry point for the scheduled scan
├── cli.py                     # local CLI entry point (no Lambda needed)
├── scanners/
│   ├── base.py                 # shared BaseScanner (tag exclusion, etc.)
│   ├── idle_ec2.py
│   ├── unattached_ebs.py
│   ├── unused_eip.py
│   ├── stale_snapshots.py
│   └── idle_load_balancer.py
├── reporting/
│   ├── formatters.py           # text/JSON report building (pure functions)
│   ├── sns_publisher.py        # publish to SNS
│   └── s3_archiver.py          # archive full JSON to S3 (Hive-partitioned)
├── config_rules/
│   ├── config_evaluator.py     # shared AWS Config event/PutEvaluations helpers
│   ├── ebs_encryption_rule.py
│   ├── security_group_rule.py
│   └── required_tags_rule.py
└── utils/
    ├── logging_utils.py        # structured JSON logging for CloudWatch Insights
    └── cloudwatch_helper.py    # GetMetricStatistics helpers

infrastructure/
├── terraform/                  # primary IaC: Lambdas, IAM, SNS, S3, Config rules
└── cloudformation/             # equivalent CloudFormation template + deploy README

tests/unit/                     # full pytest suite, mocked AWS via moto
scripts/                        # build_lambda_package.sh, run_local_scan.sh
docs/                           # architecture diagram, sample outputs
```

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/your-username/cloud-cost-compliance-automation.git
cd cloud-cost-compliance-automation
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Run the tests (no AWS needed)

```bash
pytest
# 46 passed
```

### 3. Try a local dry-run scan (uses your real AWS credentials, read-only)

```bash
./scripts/run_local_scan.sh --regions us-east-1
# or directly:
python -m cloud_compliance_scanner.cli --dry-run --regions us-east-1
```

`--dry-run` runs every scanner for real against your account but never
publishes to SNS or writes to S3 — safe to run against production to see
what it *would* report.

### 4. Deploy with Terraform

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: set notification_email, scan_regions, thresholds
terraform init
terraform plan
terraform apply
```

This creates: the scanner Lambda + EventBridge schedule, an SNS topic
(with an email subscription if you set `notification_email`), an S3
bucket for archived reports, the IAM roles (least-privilege, read-only +
narrowly-scoped writes — see [`iam_scanner.tf`](infrastructure/terraform/iam_scanner.tf)),
and the three AWS Config rules (if `enable_config_rules = true`, the
default).

**Trigger an immediate scan** after deploying, instead of waiting for the
schedule:

```bash
terraform output manual_invoke_command   # prints the exact command to run
```

### 4b. Or deploy with CloudFormation

See [`infrastructure/cloudformation/README.md`](infrastructure/cloudformation/README.md)
for the equivalent CloudFormation deployment (functionally identical
stack — same Lambdas, same SNS topic, same Config rules).

## Configuration

Every threshold is an environment variable on the Lambda (set via Terraform
variables / CloudFormation parameters, or directly if running locally).
Full list and defaults in
[`src/cloud_compliance_scanner/config.py`](src/cloud_compliance_scanner/config.py).
The most commonly tuned ones:

| Variable | Default | Meaning |
|---|---|---|
| `SCAN_REGIONS` | Lambda's own region | Comma-separated regions to scan |
| `EC2_IDLE_CPU_THRESHOLD_PCT` | `5.0` | Avg CPU% below which an instance is "idle" |
| `EC2_IDLE_LOOKBACK_DAYS` | `14` | CloudWatch history window for EC2 idleness |
| `EBS_UNATTACHED_GRACE_DAYS` | `7` | Days a volume must be unattached before flagging |
| `SNAPSHOT_MAX_AGE_DAYS` | `90` | Age above which a snapshot is "stale" |
| `ELB_IDLE_REQUEST_THRESHOLD` | `1` | Total requests below which an LB is "idle" |
| `EXCLUSION_TAG_KEYS` | `doNotDelete,scanner:ignore` | Tag keys that exempt a resource from any finding |
| `MIN_SEVERITY_TO_NOTIFY` | `LOW` | Minimum severity that triggers an SNS notification (all findings are still archived to S3 regardless) |
| `DRY_RUN` | `false` | If true, scan but never publish/archive (side-effect-free) |

## Why these design choices

**Read-only by design.** The scanner Lambda's IAM role has zero
delete/terminate/modify permissions on the resources it inspects — it can
only `Describe*`/`Get*`/`List*` plus publish to its own SNS topic and write
to its own S3 bucket. It reports; a human (or a separate, deliberately
built remediation pipeline) decides what to act on.

**Graceful degradation everywhere.** A single scanner failing (API
throttling, a region with no resources, a permissions gap) never takes
down the whole scan — the orchestrator isolates failures per
scanner-per-region and reports them separately in `errors`, while still
delivering every finding that *did* succeed.

**No metric history → no finding.** If CloudWatch has no datapoints yet
for a resource (e.g. it launched an hour ago), scanners treat that as
"not enough data" rather than guessing — avoids noisy false positives on
brand-new infrastructure.

**Lambda-backed Config rules, not just managed rules.** AWS offers a
managed `required-tags` rule that needs no Lambda at all — and the docstring
in [`required_tags_rule.py`](src/cloud_compliance_scanner/config_rules/required_tags_rule.py)
says so explicitly. The custom Lambda version is included anyway as a
**worked example** for teams that need conditional logic the managed rules
can't express, and to keep the three rules consistent in how they report
results.

**Same package for the scanner and the Config rules.** One zip, multiple
handler paths (`lambda_handler.handler`,
`config_rules.ebs_encryption_rule.handler`, etc.) — simpler to build,
version, and test than maintaining four separate deployment artifacts.

## Testing approach

The full suite (46 tests) runs against `moto`'s mocked AWS services:
EC2, EBS, ELBv2, CloudWatch, SNS, S3, and STS are all simulated in-process.
No network calls, no AWS account, no cost. A few resource types (notably
EBS snapshots, where moto's `OwnerIds=["self"]` filtering doesn't match
real AWS behavior — see the docstring in
[`test_stale_snapshots.py`](tests/unit/test_stale_snapshots.py)) use a
lightweight hand-rolled stub client instead, for more precise control.

```bash
pytest                                                    # run everything
pytest --cov=cloud_compliance_scanner --cov-report=term-missing  # with coverage
pytest tests/unit/test_idle_ec2.py -v                     # one scanner
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the test
suite on Python 3.11 and 3.12, lints with `ruff`, checks formatting with
`black`, builds the actual Lambda deployment zip and verifies every
handler imports cleanly from it (catching packaging bugs before they hit
AWS), and validates both the Terraform (`terraform validate`) and
CloudFormation (`cfn-lint`) infrastructure definitions.

## Extending it

Adding a new scanner or a new Config rule follows a consistent pattern —
see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the step-by-step. In short:
subclass `BaseScanner`, implement `scan(region)`, register it in
`orchestrator.DEFAULT_SCANNERS`, add tests, done. New Config rules follow
the same shape using `config_evaluator.put_evaluation()`.

## License

[MIT](LICENSE) — use it, fork it, adapt it for your own AWS account.
