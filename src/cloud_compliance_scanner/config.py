"""
config.py
---------
Centralized, environment-driven configuration for the scanner.

All thresholds and behavior knobs are read from environment variables so the
same Lambda artifact can be reused across dev/stage/prod by just changing
the Lambda's environment configuration (e.g. in Terraform) -- no code or
redeploy needed to tune thresholds.
"""

import os
from dataclasses import dataclass, field
from typing import List


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name)
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class ScannerConfig:
    """All tunable thresholds for the resource scanners."""

    # --- Regions to scan. Defaults to the Lambda's own region. ---
    regions: List[str] = field(
        default_factory=lambda: _env_list(
            "SCAN_REGIONS", [os.environ.get("AWS_REGION", "us-east-1")]
        )
    )

    # --- EC2 idle detection ---
    # An instance is "idle" if average CPU utilization over the lookback
    # window stays below this threshold (percent).
    ec2_idle_cpu_threshold_pct: float = field(
        default_factory=lambda: _env_float("EC2_IDLE_CPU_THRESHOLD_PCT", 5.0)
    )
    ec2_idle_lookback_days: int = field(
        default_factory=lambda: _env_int("EC2_IDLE_LOOKBACK_DAYS", 14)
    )
    # Network I/O (bytes) below which we also consider the instance idle,
    # used as a secondary signal alongside CPU.
    ec2_idle_network_bytes_threshold: int = field(
        default_factory=lambda: _env_int("EC2_IDLE_NETWORK_BYTES_THRESHOLD", 5 * 1024 * 1024)
    )

    # --- EBS unattached volume detection ---
    ebs_unattached_grace_days: int = field(
        default_factory=lambda: _env_int("EBS_UNATTACHED_GRACE_DAYS", 7)
    )

    # --- EBS stale snapshot detection ---
    snapshot_max_age_days: int = field(
        default_factory=lambda: _env_int("SNAPSHOT_MAX_AGE_DAYS", 90)
    )

    # --- Elastic IP detection ---
    # EIPs not associated with a running instance/ENI are always flaggable;
    # no threshold needed, but we keep a grace period to avoid flapping on
    # IPs that were *just* released by an instance.
    eip_grace_hours: int = field(default_factory=lambda: _env_int("EIP_GRACE_HOURS", 1))

    # --- Load Balancer idle detection ---
    elb_idle_lookback_days: int = field(
        default_factory=lambda: _env_int("ELB_IDLE_LOOKBACK_DAYS", 14)
    )
    elb_idle_request_threshold: int = field(
        default_factory=lambda: _env_int("ELB_IDLE_REQUEST_THRESHOLD", 1)
    )

    # --- Tag-based exclusion ---
    # Resources carrying any of these tag KEYS (any value) are skipped,
    # e.g. "doNotDelete" or "scanner:ignore" for known-good long-idle assets.
    exclusion_tag_keys: List[str] = field(
        default_factory=lambda: _env_list("EXCLUSION_TAG_KEYS", ["doNotDelete", "scanner:ignore"])
    )

    # --- Reporting ---
    sns_topic_arn: str = field(default_factory=lambda: os.environ.get("SNS_TOPIC_ARN", ""))
    report_bucket: str = field(default_factory=lambda: os.environ.get("REPORT_BUCKET", ""))
    report_prefix: str = field(default_factory=lambda: os.environ.get("REPORT_PREFIX", "reports/"))
    min_severity_to_notify: str = field(
        default_factory=lambda: os.environ.get("MIN_SEVERITY_TO_NOTIFY", "LOW")
    )

    # --- Estimated monthly cost rates (USD), used for cost-impact estimates ---
    # These are coarse, on-demand-style estimates meant to prioritize
    # findings, NOT to replace AWS Cost Explorer / Billing data.
    estimated_gp3_per_gb_month: float = field(
        default_factory=lambda: _env_float("EST_GP3_PER_GB_MONTH", 0.08)
    )
    estimated_eip_idle_per_hour: float = field(
        default_factory=lambda: _env_float("EST_EIP_IDLE_PER_HOUR", 0.005)
    )
    estimated_snapshot_per_gb_month: float = field(
        default_factory=lambda: _env_float("EST_SNAPSHOT_PER_GB_MONTH", 0.05)
    )

    # --- Misc ---
    dry_run: bool = field(default_factory=lambda: _env_bool("DRY_RUN", False))
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))


def get_config() -> ScannerConfig:
    """Factory so config is re-read fresh (helps tests that monkeypatch env vars)."""
    return ScannerConfig()
