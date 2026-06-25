"""
config_evaluator.py
---------------------
Shared helper code for AWS Config custom Lambda rule evaluators.

AWS Config invokes a rule's Lambda function with an event containing the
rule parameters and either:
  * a `configurationItem` (for configuration-change-triggered rules), or
  * `invokingEvent` containing a list of configurationItems (for
    periodic/scheduled rules).

This module provides `put_evaluation()` to report compliance back to
AWS Config via the config:PutEvaluations API, and `extract_configuration_item()`
to normalize both trigger styles into a single shape.
"""

import json
from typing import Optional

import boto3

from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


def extract_configuration_item(event: dict) -> Optional[dict]:
    """
    Normalize the AWS Config event into a single configurationItem dict,
    regardless of whether this was a configuration-change or scheduled
    (periodic) trigger.
    """
    invoking_event = json.loads(event["invokingEvent"])

    if "configurationItem" in invoking_event:
        return invoking_event["configurationItem"]

    if "configurationItemSummary" in invoking_event:
        return invoking_event["configurationItemSummary"]

    return None


def is_oversized_configuration_item(event: dict) -> bool:
    """AWS Config sends `configurationItemDiff` with status OVERSIZED for
    very large configuration items; callers should treat these as
    NOT_APPLICABLE rather than erroring."""
    try:
        invoking_event = json.loads(event["invokingEvent"])
        return (
            invoking_event.get("configurationItemDiff", {}).get("changeType")
            == "OVERSIZED_CONFIGURATION_ITEM"
        )
    except (KeyError, json.JSONDecodeError):
        return False


def put_evaluation(
    event: dict,
    compliance_resource_type: str,
    compliance_resource_id: str,
    compliance_type: str,
    annotation: str,
    session: boto3.Session = None,
) -> dict:
    """
    Report a single compliance evaluation back to AWS Config.

    compliance_type must be one of:
      COMPLIANT | NON_COMPLIANT | NOT_APPLICABLE | INSUFFICIENT_DATA
    """
    session = session or boto3.Session()
    config_client = session.client("config")

    # Annotation has a 256-char limit imposed by the Config API.
    annotation = (annotation or "")[:256]

    evaluation = {
        "ComplianceResourceType": compliance_resource_type,
        "ComplianceResourceId": compliance_resource_id,
        "ComplianceType": compliance_type,
        "Annotation": annotation,
        "OrderingTimestamp": json.loads(event["invokingEvent"]).get("notificationCreationTime")
        or json.loads(event["invokingEvent"])
        .get("configurationItem", {})
        .get("configurationItemCaptureTime"),
    }

    response = config_client.put_evaluations(
        Evaluations=[evaluation],
        ResultToken=event["resultToken"],
    )

    logger.info(
        "config_evaluation_submitted",
        extra={
            "extra_fields": {
                "resource_id": compliance_resource_id,
                "compliance_type": compliance_type,
            }
        },
    )

    return response
