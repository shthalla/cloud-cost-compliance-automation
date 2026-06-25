###############################################################################
# lambda_scanner.tf
#
# The scheduled scanner Lambda function + its EventBridge (CloudWatch Events)
# schedule trigger.
###############################################################################

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${local.name_prefix}-scanner"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

resource "aws_lambda_function" "scanner" {
  function_name = "${local.name_prefix}-scanner"
  description   = "Scans for idle/unused EC2, EBS, EIP, and Load Balancer resources and reports findings via SNS."

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  handler = "cloud_compliance_scanner.lambda_handler.handler"
  runtime = "python3.12"
  role    = aws_iam_role.scanner_lambda.arn

  memory_size = var.lambda_memory_mb
  timeout     = var.lambda_timeout_seconds

  environment {
    variables = {
      SCAN_REGIONS               = join(",", var.scan_regions)
      SNS_TOPIC_ARN              = aws_sns_topic.findings.arn
      REPORT_BUCKET               = aws_s3_bucket.reports.bucket
      REPORT_PREFIX               = "reports/"
      MIN_SEVERITY_TO_NOTIFY      = var.min_severity_to_notify
      EC2_IDLE_CPU_THRESHOLD_PCT  = tostring(var.ec2_idle_cpu_threshold_pct)
      EC2_IDLE_LOOKBACK_DAYS      = tostring(var.ec2_idle_lookback_days)
      EBS_UNATTACHED_GRACE_DAYS   = tostring(var.ebs_unattached_grace_days)
      SNAPSHOT_MAX_AGE_DAYS       = tostring(var.snapshot_max_age_days)
      ELB_IDLE_LOOKBACK_DAYS      = tostring(var.elb_idle_lookback_days)
      ELB_IDLE_REQUEST_THRESHOLD  = tostring(var.elb_idle_request_threshold)
      EXCLUSION_TAG_KEYS          = join(",", var.exclusion_tag_keys)
      LOG_LEVEL                   = "INFO"
      DRY_RUN                     = "false"
    }
  }

  depends_on = [aws_cloudwatch_log_group.scanner]

  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "scanner_schedule" {
  name                = "${local.name_prefix}-scanner-schedule"
  description         = "Triggers the cloud cost & compliance scanner Lambda on a schedule."
  schedule_expression = var.schedule_expression

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "scanner_schedule" {
  rule = aws_cloudwatch_event_rule.scanner_schedule.name
  arn  = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scanner_schedule.arn
}
