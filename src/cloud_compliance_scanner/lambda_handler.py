"""
lambda_handler.py
-------------------
Entry point for the scheduled scan Lambda function. Wired up via
EventBridge (e.g. "every day at 08:00 UTC" or "every Monday") in
infrastructure/terraform.

Handler signature follows the standard AWS Lambda Python contract:
    def handler(event, context) -> dict

Set the Lambda's "Handler" setting to:
    cloud_compliance_scanner.lambda_handler.handler
"""

import boto3

from cloud_compliance_scanner.config import get_config
from cloud_compliance_scanner.orchestrator import run_scan
from cloud_compliance_scanner.reporting.s3_archiver import archive_report
from cloud_compliance_scanner.reporting.sns_publisher import publish_report
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


def _get_account_id(session: boto3.Session) -> str:
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except Exception as exc:  # noqa: BLE001
        logger.warning("get_caller_identity_failed", extra={"extra_fields": {"error": str(exc)}})
        return "unknown"


def handler(event, context):
    """
    Scheduled scan handler.

    `event` is typically the EventBridge scheduled-event payload (unused
    here beyond logging), but the function also works fine if invoked
    manually/for testing with `{}`.
    """
    logger.info("lambda_invocation_started", extra={"extra_fields": {"event": event}})

    session = boto3.Session()
    config = get_config()
    account_id = _get_account_id(session)

    result = run_scan(session=session, config=config)

    s3_key = archive_report(result, config, session=session)
    sns_response = publish_report(result, config, session=session, account_id=account_id)

    response_body = {
        "account_id": account_id,
        "finding_count": len(result.findings),
        "estimated_monthly_savings_usd": result.total_estimated_monthly_savings_usd,
        "regions_scanned": result.regions_scanned,
        "error_count": len(result.errors),
        "s3_report_key": s3_key,
        "sns_message_id": (sns_response or {}).get("MessageId"),
    }

    logger.info("lambda_invocation_finished", extra={"extra_fields": response_body})

    return {
        "statusCode": 200,
        "body": response_body,
    }
