"""
test_sns_publisher.py
------------------------
Unit tests for publish_report() using moto-mocked SNS.
"""

from dataclasses import replace

from cloud_compliance_scanner.models import Finding, ResourceType, ScanResult, Severity
from cloud_compliance_scanner.reporting.sns_publisher import publish_report


def _make_result(findings):
    return ScanResult(
        findings=findings,
        scan_started_at="2026-01-01T00:00:00+00:00",
        scan_finished_at="2026-01-01T00:05:00+00:00",
        regions_scanned=["us-east-1"],
    )


def _make_finding(severity=Severity.HIGH):
    return Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id="i-123",
        region="us-east-1",
        reason="idle",
        severity=severity,
        estimated_monthly_cost_usd=20.0,
    )


def test_publish_report_returns_none_when_no_topic_configured(session, test_config):
    config = replace(test_config, sns_topic_arn="")
    result = _make_result([_make_finding()])

    response = publish_report(result, config, session=session)

    assert response is None


def test_publish_report_returns_none_in_dry_run(session, test_config):
    sns = session.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(Name="test-topic")["TopicArn"]

    config = replace(test_config, sns_topic_arn=topic_arn, dry_run=True)
    result = _make_result([_make_finding()])

    response = publish_report(result, config, session=session)

    assert response is None


def test_publish_report_publishes_when_topic_configured(session, test_config):
    sns = session.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(Name="test-topic")["TopicArn"]

    config = replace(test_config, sns_topic_arn=topic_arn, dry_run=False)
    result = _make_result([_make_finding(Severity.HIGH)])

    response = publish_report(result, config, session=session, account_id="123456789012")

    assert response is not None
    assert "MessageId" in response


def test_publish_report_skips_when_all_findings_below_threshold(session, test_config):
    sns = session.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(Name="test-topic")["TopicArn"]

    config = replace(
        test_config, sns_topic_arn=topic_arn, min_severity_to_notify="HIGH", dry_run=False
    )
    result = _make_result([_make_finding(Severity.LOW)])

    response = publish_report(result, config, session=session)

    assert response is None


def test_publish_report_sends_all_clear_for_zero_findings(session, test_config):
    sns = session.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(Name="test-topic")["TopicArn"]

    config = replace(test_config, sns_topic_arn=topic_arn, dry_run=False)
    result = _make_result([])

    response = publish_report(result, config, session=session)

    assert response is not None
