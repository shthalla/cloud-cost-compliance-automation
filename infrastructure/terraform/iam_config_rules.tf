###############################################################################
# iam_config_rules.tf
#
# IAM role for the AWS Config custom rule Lambda functions. These only need
# to call config:PutEvaluations (to report compliance back) plus base
# logging -- they receive all the resource configuration data they need
# directly in the Config-provided event payload, so no Describe* permissions
# are required here at all.
###############################################################################

resource "aws_iam_role" "config_rule_lambda" {
  count = var.enable_config_rules ? 1 : 0

  name               = "${local.name_prefix}-config-rule-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "config_rule_lambda_policy" {
  statement {
    sid       = "PutEvaluations"
    effect    = "Allow"
    actions   = ["config:PutEvaluations"]
    resources = ["*"] # config:PutEvaluations does not support resource-level scoping
  }

  statement {
    sid    = "Logging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-config-*",
      "arn:aws:logs:${data.aws_region.current.name}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-config-*:*",
    ]
  }
}

resource "aws_iam_role_policy" "config_rule_lambda" {
  count = var.enable_config_rules ? 1 : 0

  name   = "${local.name_prefix}-config-rule-policy"
  role   = aws_iam_role.config_rule_lambda[0].id
  policy = data.aws_iam_policy_document.config_rule_lambda_policy.json
}

# AWS Config needs explicit permission to invoke each rule's Lambda function.
# Granted per-function in lambda_config_rules.tf via aws_lambda_permission.
