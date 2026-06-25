"""
orchestrator.py
----------------
Runs every registered scanner across every configured region and produces
a single aggregated ScanResult. This is the function the Lambda handler
(and the local CLI) call into.
"""

from datetime import datetime, timezone
from typing import List, Type

import boto3

from cloud_compliance_scanner.config import ScannerConfig
from cloud_compliance_scanner.models import Finding, ScanResult
from cloud_compliance_scanner.scanners.base import BaseScanner
from cloud_compliance_scanner.scanners.idle_ec2 import IdleEC2Scanner
from cloud_compliance_scanner.scanners.idle_load_balancer import IdleLoadBalancerScanner
from cloud_compliance_scanner.scanners.stale_snapshots import StaleSnapshotScanner
from cloud_compliance_scanner.scanners.unattached_ebs import UnattachedEBSScanner
from cloud_compliance_scanner.scanners.unused_eip import UnusedEIPScanner
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Registry of all scanners that should run on every scheduled scan.
# Add new scanners here (and they're automatically included) -- see
# CONTRIBUTING.md for the pattern to follow when adding a new resource type.
DEFAULT_SCANNERS: List[Type[BaseScanner]] = [
    IdleEC2Scanner,
    UnattachedEBSScanner,
    UnusedEIPScanner,
    StaleSnapshotScanner,
    IdleLoadBalancerScanner,
]


def run_scan(
    session: boto3.Session = None,
    config: ScannerConfig = None,
    scanner_classes: List[Type[BaseScanner]] = None,
) -> ScanResult:
    """
    Run all scanners across all configured regions.

    Parameters
    ----------
    session: an existing boto3 Session (useful for tests / cross-account
             role assumption). Defaults to a fresh default Session.
    config:  ScannerConfig instance. Defaults to config.get_config().
    scanner_classes: override which scanners run (defaults to DEFAULT_SCANNERS).
    """
    from cloud_compliance_scanner.config import get_config

    session = session or boto3.Session()
    config = config or get_config()
    scanner_classes = scanner_classes or DEFAULT_SCANNERS

    started_at = datetime.now(timezone.utc).isoformat()
    all_findings: List[Finding] = []
    errors: List[dict] = []
    regions = config.regions

    logger.info(
        "scan_started",
        extra={
            "extra_fields": {
                "regions": regions,
                "scanners": [s.__name__ for s in scanner_classes],
            }
        },
    )

    for region in regions:
        for scanner_cls in scanner_classes:
            scanner = scanner_cls(session=session, config=config)
            try:
                findings = scanner.scan(region)
                all_findings.extend(findings)
            except Exception as exc:  # noqa: BLE001 - never let one scanner kill the whole run
                logger.error(
                    "scanner_failed",
                    extra={
                        "extra_fields": {
                            "scanner": scanner_cls.__name__,
                            "region": region,
                            "error": str(exc),
                        }
                    },
                )
                errors.append(
                    {
                        "scanner": scanner_cls.__name__,
                        "region": region,
                        "error": str(exc),
                    }
                )

    finished_at = datetime.now(timezone.utc).isoformat()

    result = ScanResult(
        findings=all_findings,
        scan_started_at=started_at,
        scan_finished_at=finished_at,
        regions_scanned=regions,
        errors=errors,
    )

    logger.info(
        "scan_finished",
        extra={
            "extra_fields": {
                "finding_count": len(all_findings),
                "error_count": len(errors),
                "estimated_monthly_savings_usd": result.total_estimated_monthly_savings_usd,
            }
        },
    )

    return result
