"""
models.py
---------
Shared data model emitted by every scanner. Keeping one normalized shape
means the reporting layer, tests, and Config rule evaluators don't need to
know anything about EC2 vs EBS vs ELB specifics.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @classmethod
    def rank(cls, value: "Severity") -> int:
        order = {cls.LOW: 0, cls.MEDIUM: 1, cls.HIGH: 2}
        return order[value]


class ResourceType(str, Enum):
    EC2_INSTANCE = "EC2_INSTANCE"
    EBS_VOLUME = "EBS_VOLUME"
    EBS_SNAPSHOT = "EBS_SNAPSHOT"
    ELASTIC_IP = "ELASTIC_IP"
    LOAD_BALANCER = "LOAD_BALANCER"


@dataclass
class Finding:
    """A single 'this resource looks wasteful / non-compliant' result."""

    resource_type: ResourceType
    resource_id: str
    region: str
    reason: str
    severity: Severity
    estimated_monthly_cost_usd: float = 0.0
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    account_id: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["resource_type"] = self.resource_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Aggregated output of running every scanner across every region."""

    findings: list
    scan_started_at: str
    scan_finished_at: str
    regions_scanned: list
    errors: list = field(default_factory=list)

    @property
    def total_estimated_monthly_savings_usd(self) -> float:
        return round(sum(f.estimated_monthly_cost_usd for f in self.findings), 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_started_at": self.scan_started_at,
            "scan_finished_at": self.scan_finished_at,
            "regions_scanned": self.regions_scanned,
            "finding_count": len(self.findings),
            "total_estimated_monthly_savings_usd": self.total_estimated_monthly_savings_usd,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
