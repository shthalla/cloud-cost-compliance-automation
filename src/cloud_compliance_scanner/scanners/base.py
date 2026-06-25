"""
base.py
-------
Common base class for all resource scanners. Each concrete scanner
implements `scan(region)` and returns a list of Finding objects.

Scanners are deliberately stateless and take a boto3 Session in their
constructor, so they're easy to unit test with moto or with hand-rolled
stub sessions.
"""

from abc import ABC, abstractmethod
from typing import Dict, List

import boto3

from cloud_compliance_scanner.config import ScannerConfig
from cloud_compliance_scanner.models import Finding
from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


class BaseScanner(ABC):
    """All scanners inherit from this."""

    #: Human-readable name used in logs.
    name: str = "base"

    def __init__(self, session: boto3.Session, config: ScannerConfig):
        self.session = session
        self.config = config

    @abstractmethod
    def scan(self, region: str) -> List[Finding]:
        """Scan a single region and return findings. Must not raise on
        recoverable per-resource errors; log and skip instead."""
        raise NotImplementedError

    def is_excluded(self, tags: Dict[str, str]) -> bool:
        """Check whether a resource carries an exclusion tag key
        (e.g. doNotDelete) and should be skipped regardless of findings."""
        if not tags:
            return False
        tag_keys_lower = {k.lower() for k in tags.keys()}
        for excluded_key in self.config.exclusion_tag_keys:
            if excluded_key.lower() in tag_keys_lower:
                return True
        return False

    @staticmethod
    def tags_from_aws_tag_list(aws_tags) -> Dict[str, str]:
        """Convert boto3's [{'Key': 'x', 'Value': 'y'}, ...] shape into a dict."""
        if not aws_tags:
            return {}
        return {t.get("Key", ""): t.get("Value", "") for t in aws_tags}
