###############################################################################
# lambda_config_rules.tf
#
# One Lambda function per custom AWS Config rule. All three share the same
# deployment package as the scanner (it's the same Python project / set of
# importable modules), just with a different handler path pointing at the
# specific rule module.
###############################################################################

resource "aws_cloudwatch_log_group" "config_ebs_encryption" {
  count = var.enable_config_rules ? 1 : 0

  name              = "/aws/lambda/${local.name_prefix}-config-ebs-encryption"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_lambda_function" "config_ebs_encryption" {
  count = var.enable_config_rules ? 1 : 0

  function_name = "${local.name_prefix}-config-ebs-encryption"
  description   = "AWS Config custom rule: flags unencrypted EBS volumes."

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  handler = "cloud_compliance_scanner.config_rules.ebs_encryption_rule.handler"
  runtime = "python3.12"
  role    = aws_iam_role.config_rule_lambda[0].arn

  memory_size = 128
  timeout     = 30

  depends_on = [aws_cloudwatch_log_group.config_ebs_encryption]
  tags       = local.common_tags
}

resource "aws_lambda_permission" "config_invoke_ebs_encryption" {
  count = var.enable_config_rules ? 1 : 0

  statement_id  = "AllowConfigInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.config_ebs_encryption[0].function_name
  principal     = "config.amazonaws.com"
}

# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "config_security_group" {
  count = var.enable_config_rules ? 1 : 0

  name              = "/aws/lambda/${local.name_prefix}-config-security-group"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_lambda_function" "config_security_group" {
  count = var.enable_config_rules ? 1 : 0

  function_name = "${local.name_prefix}-config-security-group"
  description   = "AWS Config custom rule: flags security groups with unrestricted ingress on sensitive ports."

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  handler = "cloud_compliance_scanner.config_rules.security_group_rule.handler"
  runtime = "python3.12"
  role    = aws_iam_role.config_rule_lambda[0].arn

  memory_size = 128
  timeout     = 30

  depends_on = [aws_cloudwatch_log_group.config_security_group]
  tags       = local.common_tags
}

resource "aws_lambda_permission" "config_invoke_security_group" {
  count = var.enable_config_rules ? 1 : 0

  statement_id  = "AllowConfigInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.config_security_group[0].function_name
  principal     = "config.amazonaws.com"
}

# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "config_required_tags" {
  count = var.enable_config_rules ? 1 : 0

  name              = "/aws/lambda/${local.name_prefix}-config-required-tags"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_lambda_function" "config_required_tags" {
  count = var.enable_config_rules ? 1 : 0

  function_name = "${local.name_prefix}-config-required-tags"
  description   = "AWS Config custom rule: flags resources missing required cost-allocation/ownership tags."

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  handler = "cloud_compliance_scanner.config_rules.required_tags_rule.handler"
  runtime = "python3.12"
  role    = aws_iam_role.config_rule_lambda[0].arn

  memory_size = 128
  timeout     = 30

  depends_on = [aws_cloudwatch_log_group.config_required_tags]
  tags       = local.common_tags
}

resource "aws_lambda_permission" "config_invoke_required_tags" {
  count = var.enable_config_rules ? 1 : 0

  statement_id  = "AllowConfigInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.config_required_tags[0].function_name
  principal     = "config.amazonaws.com"
}
