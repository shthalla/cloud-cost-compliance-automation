"""
cli.py
------
Command-line entry point for running a scan locally (e.g. from your laptop
with valid AWS credentials, or from a CI job) without deploying anything
to Lambda. Useful for:
  * One-off audits
  * Testing config changes before deploying
  * Running from a different scheduler entirely (cron, GitLab CI, etc.)

Usage:
    cloud-compliance-scan --regions us-east-1,us-west-2 --output report.json
    cloud-compliance-scan --dry-run
    python -m cloud_compliance_scanner.cli --help
"""

import argparse
import json
import sys

import boto3

from cloud_compliance_scanner.config import get_config
from cloud_compliance_scanner.orchestrator import run_scan
from cloud_compliance_scanner.reporting.formatters import build_text_summary
from cloud_compliance_scanner.reporting.s3_archiver import archive_report
from cloud_compliance_scanner.reporting.sns_publisher import publish_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-compliance-scan",
        description=(
            "Scan an AWS account for idle/unused EC2, EBS, EIP, and Load "
            "Balancer resources, and optionally publish a report to SNS/S3."
        ),
    )
    parser.add_argument(
        "--regions",
        type=str,
        default=None,
        help="Comma-separated list of regions to scan (overrides SCAN_REGIONS env var)",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="AWS named profile to use (defaults to the default credential chain)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write the full JSON report to this local file path",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Skip publishing to SNS even if SNS_TOPIC_ARN is configured",
    )
    parser.add_argument(
        "--no-archive",
        action="store_true",
        help="Skip archiving to S3 even if REPORT_BUCKET is configured",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run scanners and print results, but never call SNS/S3 (no side effects)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the printed text summary (still writes --output if given)",
    )
    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config = get_config()

    if args.regions:
        config.regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    if args.dry_run:
        config.dry_run = True

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    result = run_scan(session=session, config=config)

    if not args.quiet:
        print(build_text_summary(result))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        print(f"\nFull JSON report written to: {args.output}", file=sys.stderr)

    if not args.no_archive:
        archive_report(result, config, session=session)

    if not args.no_notify:
        publish_report(result, config, session=session)

    # Non-zero exit code if there were scanner errors, so CI can catch it
    return 1 if result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
