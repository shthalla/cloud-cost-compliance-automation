"""
test_idle_ec2.py
-----------------
Unit tests for IdleEC2Scanner using moto-mocked EC2 + CloudWatch.
"""

from datetime import datetime, timedelta, timezone

from cloud_compliance_scanner.scanners.idle_ec2 import IdleEC2Scanner


def _launch_instance(ec2_client, subnet_id, tags=None):
    images = ec2_client.describe_images()["Images"]
    ami_id = images[0]["ImageId"]
    tag_specs = []
    if tags:
        tag_specs = [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
            }
        ]
    resp = ec2_client.run_instances(
        ImageId=ami_id,
        InstanceType="t2.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=tag_specs,
    )
    return resp["Instances"][0]["InstanceId"]


def _put_cpu_metric(cw_client, instance_id, value, hours_ago=1):
    cw_client.put_metric_data(
        Namespace="AWS/EC2",
        MetricData=[
            {
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                "Timestamp": datetime.now(timezone.utc) - timedelta(hours=hours_ago),
                "Value": value,
                "Unit": "Percent",
            }
        ],
    )


def test_flags_instance_with_low_cpu(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    cw = session.client("cloudwatch", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]

    instance_id = _launch_instance(ec2, subnet["SubnetId"])
    _put_cpu_metric(cw, instance_id, value=1.5)

    scanner = IdleEC2Scanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == instance_id]
    assert len(matching) == 1
    assert matching[0].severity.value in ("HIGH", "MEDIUM", "LOW")
    assert "CPU utilization" in matching[0].reason


def test_does_not_flag_busy_instance(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    cw = session.client("cloudwatch", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]

    instance_id = _launch_instance(ec2, subnet["SubnetId"])
    _put_cpu_metric(cw, instance_id, value=65.0)

    scanner = IdleEC2Scanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == instance_id]
    assert len(matching) == 0


def test_does_not_flag_instance_with_no_metric_history(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]

    instance_id = _launch_instance(ec2, subnet["SubnetId"])
    # No CloudWatch data put at all -- should not be flagged (insufficient data)

    scanner = IdleEC2Scanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == instance_id]
    assert len(matching) == 0


def test_respects_exclusion_tag(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    cw = session.client("cloudwatch", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]

    instance_id = _launch_instance(ec2, subnet["SubnetId"], tags={"doNotDelete": "true"})
    _put_cpu_metric(cw, instance_id, value=0.5)

    scanner = IdleEC2Scanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == instance_id]
    assert len(matching) == 0
