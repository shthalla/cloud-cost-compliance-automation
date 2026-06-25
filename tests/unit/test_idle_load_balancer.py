"""
test_idle_load_balancer.py
-----------------------------
Unit tests for IdleLoadBalancerScanner using moto-mocked ELBv2 + CloudWatch.
"""

from datetime import datetime, timedelta, timezone

from cloud_compliance_scanner.scanners.idle_load_balancer import IdleLoadBalancerScanner


def _create_alb(elbv2_client, subnet_ids):
    resp = elbv2_client.create_load_balancer(
        Name="test-alb",
        Subnets=subnet_ids,
        Type="application",
    )
    return resp["LoadBalancers"][0]["LoadBalancerArn"]


def _dimension_value_from_arn(lb_arn: str) -> str:
    marker = "loadbalancer/"
    idx = lb_arn.find(marker)
    return lb_arn[idx + len(marker) :]


def test_flags_idle_load_balancer(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    elbv2 = session.client("elbv2", region_name="us-east-1")
    cw = session.client("cloudwatch", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet1 = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
    )["Subnet"]
    subnet2 = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b"
    )["Subnet"]

    lb_arn = _create_alb(elbv2, [subnet1["SubnetId"], subnet2["SubnetId"]])
    dimension_value = _dimension_value_from_arn(lb_arn)

    # put a zero-request datapoint so there IS metric history, just no traffic
    cw.put_metric_data(
        Namespace="AWS/ApplicationELB",
        MetricData=[
            {
                "MetricName": "RequestCount",
                "Dimensions": [{"Name": "LoadBalancer", "Value": dimension_value}],
                "Timestamp": datetime.now(timezone.utc) - timedelta(hours=2),
                "Value": 0,
                "Unit": "Count",
            }
        ],
    )

    scanner = IdleLoadBalancerScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == "test-alb"]
    assert len(matching) == 1
    assert matching[0].metadata["type"] == "application"


def test_does_not_flag_busy_load_balancer(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    elbv2 = session.client("elbv2", region_name="us-east-1")
    cw = session.client("cloudwatch", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet1 = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
    )["Subnet"]
    subnet2 = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b"
    )["Subnet"]

    lb_arn = _create_alb(elbv2, [subnet1["SubnetId"], subnet2["SubnetId"]])
    dimension_value = _dimension_value_from_arn(lb_arn)

    cw.put_metric_data(
        Namespace="AWS/ApplicationELB",
        MetricData=[
            {
                "MetricName": "RequestCount",
                "Dimensions": [{"Name": "LoadBalancer", "Value": dimension_value}],
                "Timestamp": datetime.now(timezone.utc) - timedelta(hours=2),
                "Value": 50000,
                "Unit": "Count",
            }
        ],
    )

    scanner = IdleLoadBalancerScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == "test-alb"]
    assert len(matching) == 0


def test_does_not_flag_load_balancer_with_no_metric_history(session, test_config):
    ec2 = session.client("ec2", region_name="us-east-1")
    elbv2 = session.client("elbv2", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet1 = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
    )["Subnet"]
    subnet2 = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b"
    )["Subnet"]

    _create_alb(elbv2, [subnet1["SubnetId"], subnet2["SubnetId"]])
    # No CloudWatch data at all -- should not be flagged (insufficient data)

    scanner = IdleLoadBalancerScanner(session=session, config=test_config)
    findings = scanner.scan("us-east-1")

    matching = [f for f in findings if f.resource_id == "test-alb"]
    assert len(matching) == 0
