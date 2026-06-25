"""
idle_load_balancer.py
-----------------------
Detects Application/Network Load Balancers (ELBv2) that have received
effectively zero traffic over the lookback window. An idle ALB/NLB still
bills hourly plus LCU charges, so a forgotten one is pure waste.

Classic Load Balancers are intentionally out of scope here (ELBv2 covers
the vast majority of modern deployments); contributions to add a Classic
ELB scanner are welcome -- see CONTRIBUTING.md.
"""

from typing import List

from cloud_compliance_scanner.models import Finding, ResourceType, Severity
from cloud_compliance_scanner.scanners.base import BaseScanner
from cloud_compliance_scanner.utils.cloudwatch_helper import get_sum_metric
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Coarse flat-rate hourly estimate (USD) for ALB/NLB base charge, used only
# for prioritization -- excludes LCU usage charges.
_LB_BASE_HOURLY_RATE_USD = {
    "application": 0.0225,
    "network": 0.0225,
    "gateway": 0.0125,
}


class IdleLoadBalancerScanner(BaseScanner):
    name = "idle_load_balancer"

    def scan(self, region: str) -> List[Finding]:
        findings: List[Finding] = []
        elbv2 = self.session.client("elbv2", region_name=region)
        cloudwatch = self.session.client("cloudwatch", region_name=region)

        try:
            paginator = elbv2.get_paginator("describe_load_balancers")
            load_balancers = []
            for page in paginator.paginate():
                load_balancers.extend(page.get("LoadBalancers", []))
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "elbv2_describe_load_balancers_failed",
                extra={"extra_fields": {"region": region, "error": str(exc)}},
            )
            return findings

        for lb in load_balancers:
            lb_arn = lb["LoadBalancerArn"]
            lb_name = lb["LoadBalancerName"]
            lb_type = lb.get("Type", "application")  # 'application' | 'network' | 'gateway'

            tags = self._get_tags(elbv2, lb_arn)
            if self.is_excluded(tags):
                continue

            # CloudWatch dimension format: "app/<name>/<id>" or "net/<name>/<id>"
            lb_dimension_value = self._extract_dimension_value(lb_arn)

            metric_name = "RequestCount" if lb_type == "application" else "ActiveFlowCount_TCP"
            namespace = "AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB"

            total_requests = get_sum_metric(
                cloudwatch,
                namespace=namespace,
                metric_name=metric_name,
                dimensions=[{"Name": "LoadBalancer", "Value": lb_dimension_value}],
                lookback_days=self.config.elb_idle_lookback_days,
            )

            if total_requests is None:
                continue  # no data yet, e.g. brand new LB

            if total_requests >= self.config.elb_idle_request_threshold:
                continue  # has real traffic

            hourly_rate = _LB_BASE_HOURLY_RATE_USD.get(lb_type, 0.0225)
            estimated_cost = round(hourly_rate * 24 * 30, 2)

            findings.append(
                Finding(
                    resource_type=ResourceType.LOAD_BALANCER,
                    resource_id=lb_name,
                    region=region,
                    reason=(
                        f"{lb_type.title()} load balancer received {total_requests:.0f} "
                        f"requests/flows over {self.config.elb_idle_lookback_days} days "
                        f"(threshold: {self.config.elb_idle_request_threshold})"
                    ),
                    severity=Severity.MEDIUM,
                    estimated_monthly_cost_usd=estimated_cost,
                    tags=tags,
                    metadata={
                        "load_balancer_arn": lb_arn,
                        "type": lb_type,
                        "scheme": lb.get("Scheme"),
                        "vpc_id": lb.get("VpcId"),
                        "total_requests": total_requests,
                    },
                )
            )

        logger.info(
            "idle_load_balancer_scan_complete",
            extra={
                "extra_fields": {
                    "region": region,
                    "load_balancers_checked": len(load_balancers),
                    "findings": len(findings),
                }
            },
        )
        return findings

    @staticmethod
    def _extract_dimension_value(lb_arn: str) -> str:
        """
        Convert:
          arn:aws:elasticloadbalancing:region:acct:loadbalancer/app/my-lb/1234567890abcdef
        into the CloudWatch dimension value:
          app/my-lb/1234567890abcdef
        """
        marker = "loadbalancer/"
        idx = lb_arn.find(marker)
        if idx == -1:
            return lb_arn
        return lb_arn[idx + len(marker) :]

    @staticmethod
    def _get_tags(elbv2_client, resource_arn: str) -> dict:
        try:
            response = elbv2_client.describe_tags(ResourceArns=[resource_arn])
            descriptions = response.get("TagDescriptions", [])
            if not descriptions:
                return {}
            return {t["Key"]: t["Value"] for t in descriptions[0].get("Tags", [])}
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "elbv2_describe_tags_failed",
                extra={"extra_fields": {"resource_arn": resource_arn, "error": str(exc)}},
            )
            return {}
