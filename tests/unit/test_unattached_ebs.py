"""
test_unattached_ebs.py
------------------------
Unit tests for UnattachedEBSScanner using moto-mocked EC2.

Note: moto's create_volume always sets CreateTime to "now", so to test
grace-period behavior we directly patch the volume's CreateTime via
describe_volumes mock state is not directly mutable -- instead we set the
grace period to 0 days to assert immediate-flagging behavior, and rely on
a separate assertion to confirm the grace period field is respected logic-wise
via a tiny config with grace_days=0 vs a large grace_days.
"""

from dataclasses import replace

from cloud_compliance_scanner.scanners.unattached_ebs import UnattachedEBSScanner


def test_flags_unattached_volume_past_grace_period(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    volume = ec2.create_volume(AvailabilityZone="us-east-1a", Size=50, VolumeType="gp3")
    volume_id = volume["VolumeId"]

    # zero grace period so the freshly-created (CreateTime=now) volume is flagged
    config = replace(test_config, ebs_unattached_grace_days=0)

    scanner = UnattachedEBSScanner(session=session, config=config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == volume_id]
    assert len(matching) == 1
    assert matching[0].metadata["size_gb"] == 50
    assert matching[0].estimated_monthly_cost_usd > 0


def test_does_not_flag_volume_within_grace_period(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    volume = ec2.create_volume(AvailabilityZone="us-east-1a", Size=50, VolumeType="gp3")
    volume_id = volume["VolumeId"]

    # large grace period -- freshly created volume should NOT be flagged yet
    config = replace(test_config, ebs_unattached_grace_days=30)

    scanner = UnattachedEBSScanner(session=session, config=config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == volume_id]
    assert len(matching) == 0


def test_does_not_flag_attached_volume(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    images = ec2.describe_images()["Images"]
    instance = ec2.run_instances(
        ImageId=images[0]["ImageId"],
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        SubnetId=subnet["SubnetId"],
    )["Instances"][0]

    volume = ec2.create_volume(AvailabilityZone="us-east-1a", Size=20, VolumeType="gp3")
    ec2.attach_volume(
        VolumeId=volume["VolumeId"],
        InstanceId=instance["InstanceId"],
        Device="/dev/sdf",
    )

    config = replace(test_config, ebs_unattached_grace_days=0)
    scanner = UnattachedEBSScanner(session=session, config=config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == volume["VolumeId"]]
    assert len(matching) == 0


def test_respects_exclusion_tag(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    volume = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=50,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "doNotDelete", "Value": "true"}]}
        ],
    )

    config = replace(test_config, ebs_unattached_grace_days=0)
    scanner = UnattachedEBSScanner(session=session, config=config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == volume["VolumeId"]]
    assert len(matching) == 0
