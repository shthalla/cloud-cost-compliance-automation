###############################################################################
# config_rules.tf
#
# AWS Config custom rule definitions, wired to the Lambda functions above.
#
# IMPORTANT: This module assumes AWS Config is already enabled/recording in
# this account+region (a configuration recorder + delivery channel must
# exist). Most organizations enable Config once at the account or
# Organization level, separately from individual rule sets, since enabling
# it twice causes conflicts. If you don't have Config enabled yet, see
# infrastructure/terraform/config_recorder.tf.example for a starter snippet,
# or set enable_config_rules = false and manage rules elsewhere.
###############################################################################

resource "aws_config_config_rule" "ebs_encryption" {
  count = var.enable_config_rules ? 1 : 0

  name        = "${local.name_prefix}-ebs-encryption-enabled"
  description = "Checks whether EBS volumes are encrypted. NON_COMPLIANT if a volume is not encrypted."

  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.config_ebs_encryption[0].arn

    source_detail {
      message_type = "ConfigurationItemChangeNotification"
    }
  }

  scope {
    compliance_resource_types = ["AWS::EC2::Volume"]
  }

  depends_on = [aws_lambda_permission.config_invoke_ebs_encryption]
  tags       = local.common_tags
}

resource "aws_config_config_rule" "security_group" {
  count = var.enable_config_rules ? 1 : 0

  name        = "${local.name_prefix}-restricted-security-group-ingress"
  description = "Checks whether security groups allow unrestricted ingress (0.0.0.0/0 or ::/0) on sensitive ports. NON_COMPLIANT if found."

  input_parameters = jsonencode({
    sensitivePorts = join(",", var.sensitive_security_group_ports)
  })

  source {
    owner              = "CUSTOM_LAMBDA"
    source_identifier  = aws_lambda_function.config_security_group[0].arn

    source_detail {
      message_type = "ConfigurationItemChangeNotification"
    }
  }

  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }

  depends_on = [aws_lambda_permission.config_invoke_security_group]
  tags       = local.common_tags
}

resource "aws_config_config_rule" "required_tags" {
  count = var.enable_config_rules ? 1 : 0

  name        = "${local.name_prefix}-required-tags-present"
  description = "Checks whether resources have the required cost-allocation/ownership tags. NON_COMPLIANT if any are missing."

  input_parameters = jsonencode({
    requiredTagKeys = join(",", var.required_tag_keys)
  })

  source {
    owner              = "CUSTOM_LAMBDA"
    source_identifier  = aws_lambda_function.config_required_tags[0].arn

    source_detail {
      message_type = "ConfigurationItemChangeNotification"
    }
  }

  scope {
    compliance_resource_types = [
      "AWS::EC2::Instance",
      "AWS::EC2::Volume",
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
    ]
  }

  depends_on = [aws_lambda_permission.config_invoke_required_tags]
  tags       = local.common_tags
}
