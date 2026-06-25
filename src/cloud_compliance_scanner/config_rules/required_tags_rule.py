"""
required_tags_rule.py
------------------------
AWS Config custom rule: flags resources missing one or more required tag
keys (e.g. "Environment", "Owner", "CostCenter"). This is the most common
governance rule organizations want for cost allocation and accountability.

Note: AWS also provides a managed rule (`required-tags`) that does this
without any Lambda at all. This custom version exists in the repo as a
worked example of a Lambda-backed Config rule for teams that need extra
logic the managed rule doesn't support (e.g. conditional requirements
based on resource type, or custom annotation messages). For simple "these
N tags must exist" needs, prefer the AWS managed rule -- see
infrastructure/terraform/config_rules.tf for both options side by side.

Deploy with trigger type "Configuration Changes" against whichever
resource types you care about (e.g. AWS::EC2::Instance, AWS::EC2::Volume,
AWS::ElasticLoadBalancingV2::LoadBalancer).

Lambda handler: cloud_compliance_scanner.config_rules.required_tags_rule.handler

Rule parameters:
  {
    "requiredTagKeys": "Environment,Owner,CostCenter"
  }
"""

import json

import boto3

from cloud_compliance_scanner.config_rules.config_evaluator import (
    extract_configuration_item,
    is_oversized_configuration_item,
    put_evaluation,
)
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)

_DEFAULT_REQUIRED_TAGS = ["Environment", "Owner"]


def _parse_required_tags(event: dict) -> list:
    rule_parameters_raw = event.get("ruleParameters")
    if not rule_parameters_raw:
        return _DEFAULT_REQUIRED_TAGS
    try:
        params = json.loads(rule_parameters_raw)
        tags_csv = params.get("requiredTagKeys")
        if not tags_csv:
            return _DEFAULT_REQUIRED_TAGS
        return [t.strip() for t in tags_csv.split(",") if t.strip()]
    except json.JSONDecodeError:
        logger.warning("invalid_rule_parameters_falling_back_to_defaults")
        return _DEFAULT_REQUIRED_TAGS


def handler(event, context):
    if is_oversized_configuration_item(event):
        logger.info("skipping_oversized_configuration_item")
        return

    configuration_item = extract_configuration_item(event)
    if configuration_item is None:
        logger.warning("no_configuration_item_in_event")
        return

    resource_id = configuration_item.get("resourceId")
    resource_type = configuration_item.get("resourceType", "AWS::EC2::Instance")

    if configuration_item.get("configurationItemStatus") == "ResourceDeleted":
        put_evaluation(
            event,
            compliance_resource_type=resource_type,
            compliance_resource_id=resource_id,
            compliance_type="NOT_APPLICABLE",
            annotation="Resource was deleted.",
        )
        return

    required_tags = _parse_required_tags(event)
    existing_tags = configuration_item.get("tags", {}) or {}
    existing_tag_keys = set(existing_tags.keys())

    missing = [tag for tag in required_tags if tag not in existing_tag_keys]

    if missing:
        compliance_type = "NON_COMPLIANT"
        annotation = f"Missing required tag(s): {', '.join(missing)}"
    else:
        compliance_type = "COMPLIANT"
        annotation = "All required tags present."

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
        "required_tags_rule_evaluated",
        extra={
            "extra_fields": {
                "resource_id": resource_id,
                "compliance_type": compliance_type,
                "missing_tags": missing,
            }
        },
    )
