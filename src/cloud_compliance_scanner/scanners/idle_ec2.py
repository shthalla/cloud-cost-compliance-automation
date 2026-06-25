"""
idle_ec2.py
-----------
Detects EC2 instances that are running but effectively idle, based on
average CPU utilization (and, as a secondary signal, network I/O) over a
configurable lookback window.

An instance is flagged when:
  * It is in 'running' state, AND
  * It has CloudWatch CPU history (i.e. has been up long enough to judge), AND
  * Average CPU utilization < ec2_idle_cpu_threshold_pct over the window.

Severity scales with instance size (larger idle instances cost more, so
they're higher priority) and how far below threshold the CPU usage is.
"""

from typing import List

from cloud_compliance_scanner.models import Finding, ResourceType, Severity
from cloud_compliance_scanner.scanners.base import BaseScanner
from cloud_compliance_scanner.utils.cloudwatch_helper import get_average_metric
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Coarse hourly on-demand rate table (USD) used only to rank/prioritize
# findings. Not a substitute for real billing data -- intentionally a
# small, easily-extended table rather than calling the (paginated, slow)
# Pricing API on every scan.
_INSTANCE_HOURLY_RATE_USD = {
    "t2.micro": 0.0116,
    "t2.small": 0.023,
    "t2.medium": 0.0464,
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "t3.large": 0.0832,
    "m5.large": 0.096,
    "m5.xlarge": 0.192,
    "m5.2xlarge": 0.384,
    "c5.large": 0.085,
    "c5.xlarge": 0.17,
    "r5.large": 0.126,
    "r5.xlarge": 0.252,
}
_DEFAULT_HOURLY_RATE_USD = 0.10  # fallback for instance types not in the table


def _estimate_monthly_cost(instance_type: str) -> float:
    hourly = _INSTANCE_HOURLY_RATE_USD.get(instance_type, _DEFAULT_HOURLY_RATE_USD)
    return round(hourly * 24 * 30, 2)


class IdleEC2Scanner(BaseScanner):
    name = "idle_ec2"

    def scan(self, region: str) -> List[Finding]:
        findings: List[Finding] = []
        ec2 = self.session.client("ec2", region_name=region)
        cloudwatch = self.session.client("cloudwatch", region_name=region)

        paginator = ec2.get_paginator("describe_instances")
        try:
            pages = paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )
            instances = []
            for page in pages:
                for reservation in page.get("Reservations", []):
                    instances.extend(reservation.get("Instances", []))
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "ec2_describe_instances_failed",
                extra={"extra_fields": {"region": region, "error": str(exc)}},
            )
            return findings

        for instance in instances:
            instance_id = instance["InstanceId"]
            instance_type = instance.get("InstanceType", "unknown")
            tags = self.tags_from_aws_tag_list(instance.get("Tags"))

            if self.is_excluded(tags):
                logger.info(
                    "ec2_instance_excluded_by_tag",
                    extra={"extra_fields": {"instance_id": instance_id, "region": region}},
                )
                continue

            avg_cpu = get_average_metric(
                cloudwatch,
                namespace="AWS/EC2",
                metric_name="CPUUtilization",
                dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                lookback_days=self.config.ec2_idle_lookback_days,
            )

            if avg_cpu is None:
                # No metric history yet (e.g. instance launched very recently).
                # Don't flag -- not enough data to judge.
                continue

            if avg_cpu >= self.config.ec2_idle_cpu_threshold_pct:
                continue  # not idle

            net_in = (
                get_average_metric(
                    cloudwatch,
                    namespace="AWS/EC2",
                    metric_name="NetworkIn",
                    dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                    lookback_days=self.config.ec2_idle_lookback_days,
                    stat="Sum",
                )
                or 0
            )

            estimated_cost = _estimate_monthly_cost(instance_type)

            # Severity: combine "how idle" and "how expensive"
            if avg_cpu < 1.0 and estimated_cost > 50:
                severity = Severity.HIGH
            elif avg_cpu < self.config.ec2_idle_cpu_threshold_pct / 2:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            findings.append(
                Finding(
                    resource_type=ResourceType.EC2_INSTANCE,
                    resource_id=instance_id,
                    region=region,
                    reason=(
                        f"Average CPU utilization {avg_cpu:.2f}% over "
                        f"{self.config.ec2_idle_lookback_days} days "
                        f"(threshold: {self.config.ec2_idle_cpu_threshold_pct}%), "
                        f"avg NetworkIn {net_in/1024/1024:.2f} MB/period"
                    ),
                    severity=severity,
                    estimated_monthly_cost_usd=estimated_cost,
                    tags=tags,
                    metadata={
                        "instance_type": instance_type,
                        "avg_cpu_pct": round(avg_cpu, 3),
                        "lookback_days": self.config.ec2_idle_lookback_days,
                        "launch_time": str(instance.get("LaunchTime", "")),
                        "vpc_id": instance.get("VpcId"),
                        "private_ip": instance.get("PrivateIpAddress"),
                    },
                )
            )

        logger.info(
            "idle_ec2_scan_complete",
            extra={
                "extra_fields": {
                    "region": region,
                    "instances_checked": len(instances),
                    "findings": len(findings),
                }
            },
        )
        return findings
