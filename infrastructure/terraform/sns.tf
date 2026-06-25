###############################################################################
# sns.tf
#
# SNS topic that the scanner Lambda publishes findings reports to. Subscribe
# email, Slack (via a subscriber Lambda or AWS Chatbot), SQS, or anything else
# that speaks SNS.
###############################################################################

resource "aws_sns_topic" "findings" {
  name              = "${local.name_prefix}-findings"
  kms_master_key_id = "alias/aws/sns" # SSE with the AWS-managed SNS key

  tags = local.common_tags
}

resource "aws_sns_topic_policy" "findings" {
  arn = aws_sns_topic.findings.arn

  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    sid    = "AllowLambdaPublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.findings.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AllowAccountOwnerFullAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }

    actions   = ["SNS:*"]
    resources = [aws_sns_topic.findings.arn]
  }
}

resource "aws_sns_topic_subscription" "email" {
  count = var.notification_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.findings.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_sns_topic_subscription" "additional" {
  for_each = { for idx, sub in var.notification_endpoints : idx => sub }

  topic_arn = aws_sns_topic.findings.arn
  protocol  = each.value.protocol
  endpoint  = each.value.endpoint
}
