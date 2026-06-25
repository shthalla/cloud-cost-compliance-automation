###############################################################################
# iam_scanner.tf
#
# Least-privilege IAM role for the scheduled scanner Lambda.
#
# Permission philosophy:
#   * Read-only Describe*/Get*/List* permissions across EC2/ELBv2/CloudWatch
#     so the scanner can inspect resources -- this Lambda NEVER modifies or
#     deletes any scanned resource, it only reports on them.
#   * Narrow write permissions limited to exactly: publish to OUR SNS topic,
#     and put objects under OUR S3 reports bucket.
#   * Standard CloudWatch Logs permissions scoped to this function's own
#     log group only.
###############################################################################

resource "aws_iam_role" "scanner_lambda" {
  name = "${local.name_prefix}-scanner-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "scanner_lambda_policy" {
  # --- Read-only resource inspection across all regions the scanner targets ---
  statement {
    sid    = "ReadOnlyResourceInspection"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeAddresses",
      "ec2:DescribeImages",
      "ec2:DescribeTags",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTags",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:GetMetricData",
      "cloudwatch:ListMetrics",
    ]
    resources = ["*"] # Describe/Get/List EC2 & CloudWatch APIs do not support resource-level scoping
  }

  # --- Identify which account we're running in (for report headers) ---
  statement {
    sid       = "CallerIdentity"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }

  # --- Publish ONLY to our own findings topic ---
  statement {
    sid       = "PublishFindings"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.findings.arn]
  }

  # --- Write ONLY to our own reports bucket ---
  statement {
    sid    = "ArchiveReports"
    effect = "Allow"
    actions = [
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
  }

  # --- Standard Lambda logging, scoped to this function's own log group ---
  statement {
    sid    = "Logging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-scanner*",
      "arn:aws:logs:${data.aws_region.current.name}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-scanner*:*",
    ]
  }
}

resource "aws_iam_role_policy" "scanner_lambda" {
  name   = "${local.name_prefix}-scanner-policy"
  role   = aws_iam_role.scanner_lambda.id
  policy = data.aws_iam_policy_document.scanner_lambda_policy.json
}
