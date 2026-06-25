"""
test_s3_archiver.py
----------------------
Unit tests for archive_report() using moto-mocked S3.
"""

import json
from dataclasses import replace

from cloud_compliance_scanner.models import Finding, ResourceType, ScanResult, Severity
from cloud_compliance_scanner.reporting.s3_archiver import archive_report


def _make_result():
    return ScanResult(
        findings=[
            Finding(
                resource_type=ResourceType.EBS_VOLUME,
                resource_id="vol-123",
                region="us-east-1",
                reason="unattached",
                severity=Severity.MEDIUM,
                estimated_monthly_cost_usd=8.0,
            )
        ],
        scan_started_at="2026-01-01T00:00:00+00:00",
        scan_finished_at="2026-01-01T00:05:00+00:00",
        regions_scanned=["us-east-1"],
    )


def test_archive_report_returns_none_when_no_bucket_configured(session, test_config):
    config = replace(test_config, report_bucket="")
    result = _make_result()

    key = archive_report(result, config, session=session)

    assert key is None


def test_archive_report_returns_none_in_dry_run(session, test_config):
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-reports-bucket")

    config = replace(test_config, report_bucket="test-reports-bucket", dry_run=True)
    result = _make_result()

    key = archive_report(result, config, session=session)

    assert key is None


def test_archive_report_writes_to_s3_with_hive_partitioning(session, test_config):
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-reports-bucket")

    config = replace(
        test_config, report_bucket="test-reports-bucket", report_prefix="reports/", dry_run=False
    )
    result = _make_result()

    key = archive_report(result, config, session=session)

    assert key is not None
    assert key.startswith("reports/year=")
    assert "month=" in key
    assert "day=" in key
    assert key.endswith(".json")

    obj = s3.get_object(Bucket="test-reports-bucket", Key=key)
    body = json.loads(obj["Body"].read())
    assert body["finding_count"] == 1
    assert body["findings"][0]["resource_id"] == "vol-123"
