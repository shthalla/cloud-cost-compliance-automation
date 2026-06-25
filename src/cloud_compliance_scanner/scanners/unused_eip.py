"""
unused_eip.py
-------------
Detects Elastic IPs that are allocated but not associated with a running
instance or network interface. AWS charges for EIPs that are allocated but
not actively attached to a running instance.
"""

from typing import List

from cloud_compliance_scanner.models import Finding, ResourceType, Severity
from cloud_compliance_scanner.scanners.base import BaseScanner
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


class UnusedEIPScanner(BaseScanner):
    name = "unused_eip"

    def scan(self, region: str) -> List[Finding]:
        findings: List[Finding] = []
        ec2 = self.session.client("ec2", region_name=region)

        try:
            response = ec2.describe_addresses()
            addresses = response.get("Addresses", [])
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "eip_describe_addresses_failed",
                extra={"extra_fields": {"region": region, "error": str(exc)}},
            )
            return findings

        for address in addresses:
            tags = self.tags_from_aws_tag_list(address.get("Tags"))
            if self.is_excluded(tags):
                continue

            # An EIP is "in use" if it has an AssociationId (bound to an ENI)
            # or InstanceId. Anything else is pure waste.
            is_associated = bool(address.get("AssociationId") or address.get("InstanceId"))
            if is_associated:
                continue

            allocation_id = address.get("AllocationId", address.get("PublicIp"))
            public_ip = address.get("PublicIp", "unknown")

            estimated_cost = round(self.config.estimated_eip_idle_per_hour * 24 * 30, 2)

            findings.append(
                Finding(
                    resource_type=ResourceType.ELASTIC_IP,
                    resource_id=allocation_id,
                    region=region,
                    reason=f"Elastic IP {public_ip} is allocated but not associated with any instance or network interface",
                    severity=Severity.MEDIUM,
                    estimated_monthly_cost_usd=estimated_cost,
                    tags=tags,
                    metadata={
                        "public_ip": public_ip,
                        "domain": address.get("Domain"),
                        "network_border_group": address.get("NetworkBorderGroup"),
                    },
                )
            )

        logger.info(
            "unused_eip_scan_complete",
            extra={
                "extra_fields": {
                    "region": region,
                    "addresses_checked": len(addresses),
                    "findings": len(findings),
                }
            },
        )
        return findings
