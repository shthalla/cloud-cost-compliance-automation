"""
stale_snapshots.py
--------------------
Detects EBS snapshots older than a configurable age threshold. Old
snapshots (especially manual ones with no lifecycle policy) silently
accumulate storage cost forever. We only scan snapshots owned by the
current account ('self') to avoid flagging public/shared snapshots we
don't control.
"""

from datetime import datetime, timezone
from typing import List

from cloud_compliance_scanner.models import Finding, ResourceType, Severity
from cloud_compliance_scanner.scanners.base import BaseScanner
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


class StaleSnapshotScanner(BaseScanner):
    name = "stale_snapshots"

    def scan(self, region: str) -> List[Finding]:
        findings: List[Finding] = []
        ec2 = self.session.client("ec2", region_name=region)

        paginator = ec2.get_paginator("describe_snapshots")
        try:
            pages = paginator.paginate(OwnerIds=["self"])
            snapshots = []
            for page in pages:
                snapshots.extend(page.get("Snapshots", []))
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "snapshot_describe_failed",
                extra={"extra_fields": {"region": region, "error": str(exc)}},
            )
            return findings

        now = datetime.now(timezone.utc)

        # Snapshots that are AMI-backing (used by a registered image) get
        # special treatment: still report, but lower severity, since
        # deleting them might break an AMI used for ASG launches.
        amis_response_snapshot_ids = self._get_ami_backed_snapshot_ids(ec2)

        for snapshot in snapshots:
            tags = self.tags_from_aws_tag_list(snapshot.get("Tags"))
            if self.is_excluded(tags):
                continue

            start_time = snapshot.get("StartTime")
            if start_time is None:
                continue

            age_days = (now - start_time).days
            if age_days < self.config.snapshot_max_age_days:
                continue

            snapshot_id = snapshot["SnapshotId"]
            volume_size_gb = snapshot.get("VolumeSize", 0)
            estimated_cost = round(volume_size_gb * self.config.estimated_snapshot_per_gb_month, 2)

            is_ami_backed = snapshot_id in amis_response_snapshot_ids

            if is_ami_backed:
                severity = Severity.LOW
                reason_suffix = " (backs a registered AMI -- review before deleting)"
            elif age_days > self.config.snapshot_max_age_days * 2:
                severity = Severity.HIGH
                reason_suffix = ""
            else:
                severity = Severity.MEDIUM
                reason_suffix = ""

            findings.append(
                Finding(
                    resource_type=ResourceType.EBS_SNAPSHOT,
                    resource_id=snapshot_id,
                    region=region,
                    reason=(
                        f"Snapshot is {age_days} days old "
                        f"(threshold: {self.config.snapshot_max_age_days} days), "
                        f"{volume_size_gb} GiB source volume{reason_suffix}"
                    ),
                    severity=severity,
                    estimated_monthly_cost_usd=estimated_cost,
                    tags=tags,
                    metadata={
                        "volume_id": snapshot.get("VolumeId"),
                        "volume_size_gb": volume_size_gb,
                        "age_days": age_days,
                        "is_ami_backed": is_ami_backed,
                        "description": snapshot.get("Description", ""),
                    },
                )
            )

        logger.info(
            "stale_snapshots_scan_complete",
            extra={
                "extra_fields": {
                    "region": region,
                    "snapshots_checked": len(snapshots),
                    "findings": len(findings),
                }
            },
        )
        return findings

    @staticmethod
    def _get_ami_backed_snapshot_ids(ec2_client) -> set:
        """Return the set of snapshot IDs referenced by self-owned AMIs,
        so we can lower severity / warn before suggesting deletion."""
        snapshot_ids = set()
        try:
            response = ec2_client.describe_images(Owners=["self"])
            for image in response.get("Images", []):
                for mapping in image.get("BlockDeviceMappings", []):
                    ebs = mapping.get("Ebs", {})
                    snap_id = ebs.get("SnapshotId")
                    if snap_id:
                        snapshot_ids.add(snap_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "describe_images_for_ami_check_failed",
                extra={"extra_fields": {"error": str(exc)}},
            )
        return snapshot_ids
