"""
sns_publisher.py
-----------------
Publishes the scan report to an SNS topic. Subscribers to that topic
(email, Slack via Chatbot/Lambda subscriber, SMS, another Lambda, SQS,
etc.) get notified on whatever schedule the orchestrating Lambda runs on.
"""

from typing import Optional

import boto3

from cloud_compliance_scanner.config import ScannerConfig
from cloud_compliance_scanner.models import ScanResult
from cloud_compliance_scanner.reporting.formatters import (
    build_subject,
    build_text_summary,
    filter_by_min_severity,
)
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)

# SNS hard-limits message size to 256KB; truncate well before that so we
# never hit a publish error on huge accounts.
_MAX_SNS_MESSAGE_CHARS = 100_000


def publish_report(
    result: ScanResult,
    config: ScannerConfig,
    session: boto3.Session = None,
    account_id: Optional[str] = None,
) -> Optional[dict]:
    """
    Publish a formatted report to the configured SNS topic.

    Returns the SNS publish() response, or None if no topic is configured
    (useful for local/dry-run testing without requiring SNS setup) or if
    DRY_RUN is enabled.
    """
    if not config.sns_topic_arn:
        logger.warning("sns_topic_arn_not_configured_skipping_publish")
        return None

    # Only notify on findings meeting the minimum configured severity, but
    # still send a "all clear" message if there genuinely were zero findings.
    notifiable_findings = filter_by_min_severity(result.findings, config.min_severity_to_notify)

    if not notifiable_findings and result.findings:
        logger.info(
            "all_findings_below_notification_threshold",
            extra={
                "extra_fields": {
                    "min_severity_to_notify": config.min_severity_to_notify,
                    "total_findings": len(result.findings),
                }
            },
        )
        return None

    # Build a result view limited to notifiable findings for the message body,
    # but keep totals reflecting only what we're actually telling people about.
    from dataclasses import replace

    notify_result = replace(result, findings=notifiable_findings)

    message = build_text_summary(notify_result, account_id=account_id)
    subject = build_subject(notify_result)

    if len(message) > _MAX_SNS_MESSAGE_CHARS:
        message = (
            message[:_MAX_SNS_MESSAGE_CHARS]
            + "\n\n... [truncated, see full report in S3 for complete details]"
        )

    if config.dry_run:
        logger.info(
            "dry_run_skipping_sns_publish",
            extra={"extra_fields": {"subject": subject, "message_length": len(message)}},
        )
        return None

    session = session or boto3.Session()
    sns = session.client("sns")

    try:
        response = sns.publish(
            TopicArn=config.sns_topic_arn,
            Subject=subject,
            Message=message,
        )
        logger.info(
            "sns_publish_succeeded",
            extra={"extra_fields": {"message_id": response.get("MessageId")}},
        )
        return response
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "sns_publish_failed",
            extra={"extra_fields": {"error": str(exc), "topic_arn": config.sns_topic_arn}},
        )
        raise
