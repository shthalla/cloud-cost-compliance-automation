"""
ebs_encryption_rule.py
------------------------
AWS Config custom rule: flags EBS volumes that are not encrypted.

Deploy as a Lambda-backed Config Rule (see infrastructure/terraform) with
trigger type "Configuration Changes" on resource type AWS::EC2::Volume,
so this evaluates automatically every time a volume is created or its
configuration changes -- true continuous drift detection, not just a
periodic scan.

Lambda handler: cloud_compliance_scanner.config_rules.ebs_encryption_rule.handler
"""

import boto3

from cloud_compliance_scanner.config_rules.config_evaluator import (
    extract_configuration_item,
    is_oversized_configuration_item,
    put_evaluation,
)
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


def handler(event, context):
    if is_oversized_configuration_item(event):
        logger.info("skipping_oversized_configuration_item")
        return

    configuration_item = extract_configuration_item(event)
    if configuration_item is None:
        logger.warning("no_configuration_item_in_event")
        return

    resource_id = configuration_item.get("resourceId")
    resource_type = configuration_item.get("resourceType", "AWS::EC2::Volume")

    # Deleted resources are reported NOT_APPLICABLE -- there's nothing left to evaluate.
    if configuration_item.get("configurationItemStatus") == "ResourceDeleted":
        put_evaluation(
            event,
            compliance_resource_type=resource_type,
            compliance_resource_id=resource_id,
            compliance_type="NOT_APPLICABLE",
            annotation="Resource was deleted.",
        )
        return

    configuration = configuration_item.get("configuration", {})
    encrypted = configuration.get("encrypted", False)

    if encrypted:
        compliance_type = "COMPLIANT"
        annotation = "EBS volume is encrypted."
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "EBS volume is NOT encrypted. Enable encryption-by-default or recreate from an encrypted snapshot."

    session = boto3.Session()
    put_evaluation(
        event,
        compliance_resource_type=resource_type,
        compliance_resource_id=resource_id,
        compliance_type=compliance_type,
        annotation=annotation,
        session=session,
    )

    logger.info(
        "ebs_encryption_rule_evaluated",
        extra={
            "extra_fields": {
                "resource_id": resource_id,
                "compliance_type": compliance_type,
            }
        },
    )
