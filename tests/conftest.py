"""
conftest.py
-----------
Shared pytest fixtures. Uses moto to mock AWS services so the entire test
suite runs with zero real AWS calls, zero cost, and zero credentials
required -- safe to run in any CI environment, including public GitHub
Actions runners with no AWS secrets configured.
"""

import os

import boto3
import pytest
from moto import mock_aws

from cloud_compliance_scanner.config import ScannerConfig


@pytest.fixture(autouse=True)
def aws_credentials_env():
    """Ensure boto3 never accidentally tries to use real credentials during tests."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def aws(aws_credentials_env):
    """Active moto mock context for all AWS services used by this project."""
    with mock_aws():
        yield


@pytest.fixture
def session(aws):
    return boto3.Session(region_name="us-east-1")


@pytest.fixture
def test_config():
    return ScannerConfig(
        regions=["us-east-1"],
        ec2_idle_cpu_threshold_pct=5.0,
        ec2_idle_lookback_days=14,
        ebs_unattached_grace_days=7,
        snapshot_max_age_days=90,
        eip_grace_hours=1,
        elb_idle_lookback_days=14,
        elb_idle_request_threshold=1,
        exclusion_tag_keys=["doNotDelete", "scanner:ignore"],
        sns_topic_arn="",
        report_bucket="",
        dry_run=False,
    )
