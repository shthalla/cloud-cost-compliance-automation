"""
s3_archiver.py
----------------
Optionally archives the full JSON scan result to S3, so you have a
queryable history of every scan (useful for trend dashboards, Athena
queries over time, or just an audit trail) beyond what fits in an SNS
message.
"""

import json
from datetime import datetime, timezone
from typing import Optional

import boto3

from cloud_compliance_scanner.config import ScannerConfig
from cloud_compliance_scanner.models import ScanResult
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


def archive_report(
    result: ScanResult,
    config: ScannerConfig,
    session: boto3.Session = None,
) -> Optional[str]:
    """
    Write the full JSON report to S3 under:
      <report_prefix>/year=YYYY/month=MM/day=DD/scan-<timestamp>.json

    The Hive-style partitioning (year=/month=/day=) makes this directly
    queryable from Athena without any extra setup.

    Returns the S3 object key, or None if no bucket is configured or
    DRY_RUN is enabled.
    """
    if not config.report_bucket:
        logger.warning("report_bucket_not_configured_skipping_archive")
        return None

    if config.dry_run:
        logger.info("dry_run_skipping_s3_archive")
        return None

    now = datetime.now(timezone.utc)
    key = (
        f"{config.report_prefix.rstrip('/')}/"
        f"year={now.year:04d}/month={now.month:02d}/day={now.day:02d}/"
        f"scan-{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    )

    session = session or boto3.Session()
    s3 = session.client("s3")

    body = json.dumps(result.to_dict(), indent=2, default=str)

    try:
        s3.put_object(
            Bucket=config.report_bucket,
            Key=key,
            Body=body.encode("utf-8"),
            ContentType="application/json",
        )
        logger.info(
            "s3_archive_succeeded",
            extra={"extra_fields": {"bucket": config.report_bucket, "key": key}},
        )
        return key
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "s3_archive_failed",
            extra={"extra_fields": {"error": str(exc), "bucket": config.report_bucket}},
        )
        raise
