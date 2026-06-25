"""
test_config_rules.py
------------------------
Unit tests for the AWS Config custom rule Lambda handlers. We build
event payloads matching AWS Config's real invocation contract for
Lambda-backed rules and capture put_evaluations calls via a stub
'config' client to assert the right compliance verdicts are produced --
without needing moto's Config support (which doesn't cover custom rule
evaluation flows) or real AWS access.
"""

import json
from unittest.mock import MagicMock

import pytest

from cloud_compliance_scanner.config_rules import (
    ebs_encryption_rule,
    required_tags_rule,
    security_group_rule,
)


class _StubSession:
    def __init__(self, config_client):
        self._config_client = config_client

    def client(self, service_name):
        assert service_name == "config"
        return self._config_client


@pytest.fixture
def stub_config_client():
    client = MagicMock()
    client.put_evaluations.return_value = {"FailedEvaluations": []}
    return client


def _build_event(configuration_item, rule_parameters=None):
    invoking_event = {"configurationItem": configuration_item}
    event = {
        "invokingEvent": json.dumps(invoking_event),
        "resultToken": "test-token",
    }
    if rule_parameters is not None:
        event["ruleParameters"] = json.dumps(rule_parameters)
    return event


# ---------------------------------------------------------------------------
# EBS encryption rule
# ---------------------------------------------------------------------------


def test_ebs_encryption_rule_flags_unencrypted_volume(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.ebs_encryption_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "vol-123",
            "resourceType": "AWS::EC2::Volume",
            "configurationItemStatus": "OK",
            "configuration": {"encrypted": False},
        }
    )

    ebs_encryption_rule.handler(event, None)

    stub_config_client.put_evaluations.assert_called_once()
    call_kwargs = stub_config_client.put_evaluations.call_args.kwargs
    evaluation = call_kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "NON_COMPLIANT"
    assert evaluation["ComplianceResourceId"] == "vol-123"


def test_ebs_encryption_rule_passes_encrypted_volume(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.ebs_encryption_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "vol-456",
            "resourceType": "AWS::EC2::Volume",
            "configurationItemStatus": "OK",
            "configuration": {"encrypted": True},
        }
    )

    ebs_encryption_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "COMPLIANT"


def test_ebs_encryption_rule_handles_deleted_resource(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.ebs_encryption_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "vol-789",
            "resourceType": "AWS::EC2::Volume",
            "configurationItemStatus": "ResourceDeleted",
        }
    )

    ebs_encryption_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "NOT_APPLICABLE"


# ---------------------------------------------------------------------------
# Security group rule
# ---------------------------------------------------------------------------


def test_security_group_rule_flags_open_ssh(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.security_group_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "sg-123",
            "resourceType": "AWS::EC2::SecurityGroup",
            "configurationItemStatus": "OK",
            "configuration": {
                "ipPermissions": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipv4Ranges": [{"cidrIp": "0.0.0.0/0"}],
                    }
                ]
            },
        }
    )

    security_group_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "NON_COMPLIANT"
    assert "22" in evaluation["Annotation"]


def test_security_group_rule_flags_all_traffic_open(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.security_group_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "sg-999",
            "resourceType": "AWS::EC2::SecurityGroup",
            "configurationItemStatus": "OK",
            "configuration": {
                "ipPermissions": [
                    {
                        "ipProtocol": "-1",
                        "ipv4Ranges": [{"cidrIp": "0.0.0.0/0"}],
                    }
                ]
            },
        }
    )

    security_group_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "NON_COMPLIANT"
    assert "ALL traffic" in evaluation["Annotation"]


def test_security_group_rule_allows_restricted_ingress(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.security_group_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "sg-456",
            "resourceType": "AWS::EC2::SecurityGroup",
            "configurationItemStatus": "OK",
            "configuration": {
                "ipPermissions": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 443,
                        "toPort": 443,
                        "ipv4Ranges": [{"cidrIp": "0.0.0.0/0"}],
                    },
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipv4Ranges": [{"cidrIp": "10.0.0.0/16"}],
                    },
                ]
            },
        }
    )

    security_group_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    # 443 open to the world is not in the default sensitive ports list, and
    # SSH is restricted to a private CIDR, so this should be compliant.
    assert evaluation["ComplianceType"] == "COMPLIANT"


def test_security_group_rule_respects_custom_sensitive_ports(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.security_group_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "sg-789",
            "resourceType": "AWS::EC2::SecurityGroup",
            "configurationItemStatus": "OK",
            "configuration": {
                "ipPermissions": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 8080,
                        "toPort": 8080,
                        "ipv4Ranges": [{"cidrIp": "0.0.0.0/0"}],
                    }
                ]
            },
        },
        rule_parameters={"sensitivePorts": "8080"},
    )

    security_group_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "NON_COMPLIANT"


# ---------------------------------------------------------------------------
# Required tags rule
# ---------------------------------------------------------------------------


def test_required_tags_rule_flags_missing_tags(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.required_tags_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "i-abc",
            "resourceType": "AWS::EC2::Instance",
            "configurationItemStatus": "OK",
            "tags": {"Environment": "prod"},
        },
        rule_parameters={"requiredTagKeys": "Environment,Owner,CostCenter"},
    )

    required_tags_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "NON_COMPLIANT"
    assert "Owner" in evaluation["Annotation"]
    assert "CostCenter" in evaluation["Annotation"]


def test_required_tags_rule_passes_when_all_tags_present(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.required_tags_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "i-def",
            "resourceType": "AWS::EC2::Instance",
            "configurationItemStatus": "OK",
            "tags": {"Environment": "prod", "Owner": "team-x"},
        },
        rule_parameters={"requiredTagKeys": "Environment,Owner"},
    )

    required_tags_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "COMPLIANT"


def test_required_tags_rule_uses_defaults_when_no_parameters_given(monkeypatch, stub_config_client):
    monkeypatch.setattr(
        "cloud_compliance_scanner.config_rules.required_tags_rule.boto3.Session",
        lambda: _StubSession(stub_config_client),
    )

    event = _build_event(
        {
            "resourceId": "i-ghi",
            "resourceType": "AWS::EC2::Instance",
            "configurationItemStatus": "OK",
            "tags": {},
        }
    )

    required_tags_rule.handler(event, None)

    evaluation = stub_config_client.put_evaluations.call_args.kwargs["Evaluations"][0]
    assert evaluation["ComplianceType"] == "NON_COMPLIANT"
    assert "Environment" in evaluation["Annotation"]
    assert "Owner" in evaluation["Annotation"]
