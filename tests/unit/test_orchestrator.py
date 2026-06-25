"""
test_orchestrator.py
------------------------
Tests that the orchestrator correctly aggregates findings across scanners
and regions, and that a single failing scanner doesn't take down the rest
of the scan.
"""

from dataclasses import replace

from cloud_compliance_scanner.models import Finding, ResourceType, Severity
from cloud_compliance_scanner.orchestrator import run_scan
from cloud_compliance_scanner.scanners.base import BaseScanner


class _AlwaysFindsOneScanner(BaseScanner):
    name = "always_finds_one"

    def scan(self, region):
        return [
            Finding(
                resource_type=ResourceType.EC2_INSTANCE,
                resource_id=f"i-{region}",
                region=region,
                reason="stub finding",
                severity=Severity.LOW,
                estimated_monthly_cost_usd=5.0,
            )
        ]


class _AlwaysFailsScanner(BaseScanner):
    name = "always_fails"

    def scan(self, region):
        raise RuntimeError("simulated AWS API failure")


def test_run_scan_aggregates_findings_across_regions(session, test_config):
    config = replace(test_config, regions=["us-east-1", "us-west-2"])

    result = run_scan(session=session, config=config, scanner_classes=[_AlwaysFindsOneScanner])

    assert len(result.findings) == 2
    resource_ids = {f.resource_id for f in result.findings}
    assert resource_ids == {"i-us-east-1", "i-us-west-2"}
    assert len(result.errors) == 0


def test_run_scan_continues_after_scanner_failure(session, test_config):
    config = replace(test_config, regions=["us-east-1"])

    result = run_scan(
        session=session,
        config=config,
        scanner_classes=[_AlwaysFailsScanner, _AlwaysFindsOneScanner],
    )

    # the failing scanner should not prevent the working scanner's findings
    assert len(result.findings) == 1
    assert result.findings[0].resource_id == "i-us-east-1"
    assert len(result.errors) == 1
    assert result.errors[0]["scanner"] == "_AlwaysFailsScanner"


def test_total_estimated_monthly_savings_sums_correctly(session, test_config):
    config = replace(test_config, regions=["us-east-1", "us-west-2", "eu-west-1"])

    result = run_scan(session=session, config=config, scanner_classes=[_AlwaysFindsOneScanner])

    assert result.total_estimated_monthly_savings_usd == 15.0
