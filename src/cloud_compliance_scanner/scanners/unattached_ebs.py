"""
unattached_ebs.py
------------------
Detects EBS volumes in 'available' state (i.e. not attached to any
instance). These are pure waste: you pay for provisioned capacity whether
or not anything uses them.

A grace period (ebs_unattached_grace_days) avoids flagging volumes that
were *just* detached as part of a normal workflow (e.g. AMI creation,
instance replacement) -- we only flag volumes that have been sitting
unattached longer than the grace period.
"""

from datetime import datetime, timezone
from typing import List

from cloud_compliance_scanner.models import Finding, ResourceType, Severity
from cloud_compliance_scanner.scanners.base import BaseScanner
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


class UnattachedEBSScanner(BaseScanner):
    name = "unattached_ebs"

    def scan(self, region: str) -> List[Finding]:
        findings: List[Finding] = []
        ec2 = self.session.client("ec2", region_name=region)

        paginator = ec2.get_paginator("describe_volumes")
        try:
            pages = paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}])
            volumes = []
            for page in pages:
                volumes.extend(page.get("Volumes", []))
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "ebs_describe_volumes_failed",
                extra={"extra_fields": {"region": region, "error": str(exc)}},
            )
            return findings

        now = datetime.now(timezone.utc)

        for volume in volumes:
            volume_id = volume["VolumeId"]
            tags = self.tags_from_aws_tag_list(volume.get("Tags"))

            if self.is_excluded(tags):
                continue

            create_time = volume.get("CreateTime")
            if create_time is None:
                continue

            age_days = (now - create_time).days

            if age_days < self.config.ebs_unattached_grace_days:
                continue  # within grace period, might just have been detached

            size_gb = volume.get("Size", 0)
            volume_type = volume.get("VolumeType", "gp2")
            estimated_cost = round(size_gb * self.config.estimated_gp3_per_gb_month, 2)

            if age_days > 30 and size_gb >= 100:
                severity = Severity.HIGH
            elif age_days > 14:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            findings.append(
                Finding(
                    resource_type=ResourceType.EBS_VOLUME,
                    resource_id=volume_id,
                    region=region,
                    reason=(
                        f"Volume unattached for {age_days} days "
                        f"(grace period: {self.config.ebs_unattached_grace_days} days), "
                        f"{size_gb} GiB {volume_type}"
                    ),
                    severity=severity,
                    estimated_monthly_cost_usd=estimated_cost,
                    tags=tags,
                    metadata={
                        "size_gb": size_gb,
                        "volume_type": volume_type,
                        "availability_zone": volume.get("AvailabilityZone"),
                        "age_days": age_days,
                        "encrypted": volume.get("Encrypted", False),
                    },
                )
            )

        logger.info(
            "unattached_ebs_scan_complete",
            extra={
                "extra_fields": {
                    "region": region,
                    "volumes_checked": len(volumes),
                    "findings": len(findings),
                }
            },
        )
        return findings
