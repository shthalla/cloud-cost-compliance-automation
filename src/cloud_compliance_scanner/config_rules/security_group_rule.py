"""
security_group_rule.py
-------------------------
AWS Config custom rule: flags security groups that allow unrestricted
ingress (0.0.0.0/0 or ::/0) on commonly-sensitive ports (SSH/22, RDP/3389,
and a configurable extra list), or that allow ALL traffic/ports from
anywhere.

Deploy as a Lambda-backed Config Rule with trigger type "Configuration
Changes" on resource type AWS::EC2::SecurityGroup.

Lambda handler: cloud_compliance_scanner.config_rules.security_group_rule.handler

Rule parameters (set in the Config Rule definition, passed through as
event['ruleParameters'] JSON):
  {
    "sensitivePorts": "22,3389,3306,5432"   # optional, defaults below
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

_DEFAULT_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _parse_sensitive_ports(event: dict) -> set:
    rule_parameters_raw = event.get("ruleParameters")
    if not rule_parameters_raw:
        return _DEFAULT_SENSITIVE_PORTS
    try:
        params = json.loads(rule_parameters_raw)
        ports_csv = params.get("sensitivePorts")
        if not ports_csv:
            return _DEFAULT_SENSITIVE_PORTS
        return {int(p.strip()) for p in ports_csv.split(",") if p.strip()}
    except (json.JSONDecodeError, ValueError):
        logger.warning("invalid_rule_parameters_falling_back_to_defaults")
        return _DEFAULT_SENSITIVE_PORTS


def _violates(ip_permissions: list, sensitive_ports: set) -> list:
    """Return a list of human-readable violation descriptions, if any."""
    violations = []

    for permission in ip_permissions:
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort")
        ip_protocol = permission.get("ipProtocol")

        open_ranges = [
            r.get("cidrIp")
            for r in permission.get("ipv4Ranges", [])
            if r.get("cidrIp") in _OPEN_CIDRS
        ] + [
            r.get("cidrIpv6")
            for r in permission.get("ipv6Ranges", [])
            if r.get("cidrIpv6") in _OPEN_CIDRS
        ]

        if not open_ranges:
            continue

        # ipProtocol == "-1" means ALL traffic, all ports
        if ip_protocol == "-1":
            violations.append("allows ALL traffic on ALL ports from 0.0.0.0/0 or ::/0")
            continue

        if from_port is None or to_port is None:
            continue

        port_range = set(range(from_port, to_port + 1))
        intersecting = port_range & sensitive_ports
        if intersecting:
            violations.append(
                f"allows {ip_protocol.upper()} ports {sorted(intersecting)} "
                f"from 0.0.0.0/0 or ::/0"
            )

    return violations


def handler(event, context):
    if is_oversized_configuration_item(event):
        logger.info("skipping_oversized_configuration_item")
        return

    configuration_item = extract_configuration_item(event)
    if configuration_item is None:
        logger.warning("no_configuration_item_in_event")
        return

    resource_id = configuration_item.get("resourceId")
    resource_type = configuration_item.get("resourceType", "AWS::EC2::SecurityGroup")

    if configuration_item.get("configurationItemStatus") == "ResourceDeleted":
        put_evaluation(
            event,
            compliance_resource_type=resource_type,
            compliance_resource_id=resource_id,
            compliance_type="NOT_APPLICABLE",
            annotation="Resource was deleted.",
        )
        return

    sensitive_ports = _parse_sensitive_ports(event)
    configuration = configuration_item.get("configuration", {})
    ip_permissions = configuration.get("ipPermissions", [])

    violations = _violates(ip_permissions, sensitive_ports)

    if violations:
        compliance_type = "NON_COMPLIANT"
        annotation = "Unrestricted ingress detected: " + "; ".join(violations)
    else:
        compliance_type = "COMPLIANT"
        annotation = "No unrestricted ingress on sensitive ports detected."

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
        "security_group_rule_evaluated",
        extra={
            "extra_fields": {
                "resource_id": resource_id,
                "compliance_type": compliance_type,
                "violation_count": len(violations),
            }
        },
    )
