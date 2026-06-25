"""
test_stale_snapshots.py
--------------------------
Unit tests for StaleSnapshotScanner.

We use a lightweight stub boto3 client here instead of moto, because
moto's describe_snapshots(OwnerIds=["self"]) currently returns moto's
large built-in catalog of public AMI-backing snapshots in addition to
ones we create (a known moto quirk -- real AWS correctly scopes
OwnerIds=["self"] to just the caller's account). A stub gives us full
control over exactly what describe_snapshots/describe_images return,
which is both simpler and more reliable for this scanner's tests.
"""

from datetime import datetime, timedelta, timezone

from cloud_compliance_scanner.scanners.stale_snapshots import StaleSnapshotScanner


class _StubPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class _StubEC2Client:
    """Minimal stand-in for a boto3 EC2 client, returning canned data."""

    def __init__(self, snapshots, images=None):
        self._snapshots = snapshots
        self._images = images or []

    def get_paginator(self, operation_name):
        assert operation_name == "describe_snapshots"
        return _StubPaginator([{"Snapshots": self._snapshots}])

    def describe_images(self, **kwargs):
        return {"Images": self._images}


class _StubSession:
    def __init__(self, ec2_client):
        self._ec2_client = ec2_client

    def client(self, service_name, region_name=None):
        assert service_name == "ec2"
        return self._ec2_client


def test_flags_old_snapshot(test_config):
    old_time = datetime.now(timezone.utc) - timedelta(days=120)
    snapshots = [
        {
            "SnapshotId": "snap-old123",
            "VolumeId": "vol-abc",
            "VolumeSize": 30,
            "StartTime": old_time,
            "Tags": [],
            "Description": "test snapshot",
        }
    ]
    stub_client = _StubEC2Client(snapshots=snapshots, images=[])
    session = _StubSession(stub_client)

    scanner = StaleSnapshotScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_id == "snap-old123"
    assert finding.metadata["age_days"] >= 119
    assert finding.metadata["volume_size_gb"] == 30
    assert finding.metadata["is_ami_backed"] is False


def test_does_not_flag_recent_snapshot(test_config):
    recent_time = datetime.now(timezone.utc) - timedelta(days=5)
    snapshots = [
        {
            "SnapshotId": "snap-recent123",
            "VolumeId": "vol-abc",
            "VolumeSize": 30,
            "StartTime": recent_time,
            "Tags": [],
            "Description": "",
        }
    ]
    stub_client = _StubEC2Client(snapshots=snapshots, images=[])
    session = _StubSession(stub_client)

    scanner = StaleSnapshotScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    assert len(findings) == 0


def test_ami_backed_snapshot_gets_low_severity(test_config):
    old_time = datetime.now(timezone.utc) - timedelta(days=120)
    snapshots = [
        {
            "SnapshotId": "snap-amibacked",
            "VolumeId": "vol-abc",
            "VolumeSize": 8,
            "StartTime": old_time,
            "Tags": [],
            "Description": "",
        }
    ]
    images = [
        {
            "ImageId": "ami-123",
            "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-amibacked"}}],
        }
    ]
    stub_client = _StubEC2Client(snapshots=snapshots, images=images)
    session = _StubSession(stub_client)

    scanner = StaleSnapshotScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    assert len(findings) == 1
    assert findings[0].metadata["is_ami_backed"] is True
    assert findings[0].severity.value == "LOW"


def test_respects_exclusion_tag(test_config):
    old_time = datetime.now(timezone.utc) - timedelta(days=120)
    snapshots = [
        {
            "SnapshotId": "snap-excluded",
            "VolumeId": "vol-abc",
            "VolumeSize": 30,
            "StartTime": old_time,
            "Tags": [{"Key": "doNotDelete", "Value": "true"}],
            "Description": "",
        }
    ]
    stub_client = _StubEC2Client(snapshots=snapshots, images=[])
    session = _StubSession(stub_client)

    scanner = StaleSnapshotScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    assert len(findings) == 0
