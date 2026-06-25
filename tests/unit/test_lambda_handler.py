"""
test_lambda_handler.py
-------------------------
End-to-end style test for the Lambda handler: spins up moto-mocked EC2/SNS/S3,
creates a couple of wasteful resources, invokes the handler exactly the way
AWS Lambda would, and checks the response shape and that a report was
actually published/archived.
"""

import os

import boto3
import pytest
from moto import mock_aws

from cloud_compliance_scanner.lambda_handler import handler


@pytest.fixture
def lambda_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("SCAN_REGIONS", "us-east-1")
    monkeypatch.setenv("DRY_RUN", "false")


def test_handler_runs_end_to_end_and_reports(lambda_env):
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")

        sns = session.client("sns")
        topic_arn = sns.create_topic(Name="findings-topic")["TopicArn"]
        os.environ["SNS_TOPIC_ARN"] = topic_arn

        s3 = session.client("s3")
        s3.create_bucket(Bucket="findings-bucket")
        os.environ["REPORT_BUCKET"] = "findings-bucket"

        # create an unattached EBS volume so there's at least one finding
        ec2 = session.client("ec2")
        ec2.create_volume(AvailabilityZone="us-east-1a", Size=100, VolumeType="gp3")
        os.environ["EBS_UNATTACHED_GRACE_DAYS"] = "0"

        result = handler({}, None)

        assert result["statusCode"] == 200
        body = result["body"]
        assert body["finding_count"] >= 1
        assert body["s3_report_key"] is not None
        assert body["sns_message_id"] is not None
        assert body["account_id"] == "123456789012"

    # clean up env vars we set for this test
    for var in ("SNS_TOPIC_ARN", "REPORT_BUCKET", "EBS_UNATTACHED_GRACE_DAYS"):
        os.environ.pop(var, None)


def test_handler_works_with_no_findings_and_no_sinks_configured(lambda_env):
    with mock_aws():
        # No SNS topic, no S3 bucket, no resources -- should still succeed cleanly.
        for var in ("SNS_TOPIC_ARN", "REPORT_BUCKET"):
            os.environ.pop(var, None)

        result = handler({}, None)

        assert result["statusCode"] == 200
        body = result["body"]
        assert body["finding_count"] == 0
        assert body["s3_report_key"] is None
        assert body["sns_message_id"] is None
