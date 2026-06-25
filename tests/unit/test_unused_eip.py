"""
test_unused_eip.py
--------------------
Unit tests for UnusedEIPScanner using moto-mocked EC2.
"""

from cloud_compliance_scanner.scanners.unused_eip import UnusedEIPScanner


def test_flags_unassociated_eip(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    eip = ec2.allocate_address(Domain="vpc")
    allocation_id = eip["AllocationId"]

    scanner = UnusedEIPScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == allocation_id]
    assert len(matching) == 1
    assert matching[0].metadata["public_ip"] == eip["PublicIp"]


def test_does_not_flag_associated_eip(session, test_config):
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

    eip = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=eip["AllocationId"], InstanceId=instance["InstanceId"])

    scanner = UnusedEIPScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == eip["AllocationId"]]
    assert len(matching) == 0


def test_respects_exclusion_tag(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    eip = ec2.allocate_address(Domain="vpc")
    ec2.create_tags(
        Resources=[eip["AllocationId"]],
        Tags=[{"Key": "doNotDelete", "Value": "true"}],
    )

    scanner = UnusedEIPScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == eip["AllocationId"]]
    assert len(matching) == 0
