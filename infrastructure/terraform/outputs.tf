###############################################################################
# outputs.tf
###############################################################################

output "sns_topic_arn" {
  description = "ARN of the SNS topic findings reports are published to. Subscribe additional endpoints here if needed."
  value       = aws_sns_topic.findings.arn
}

output "reports_bucket_name" {
  description = "Name of the S3 bucket where full JSON scan reports are archived."
  value       = aws_s3_bucket.reports.bucket
}

output "scanner_lambda_function_name" {
  description = "Name of the scheduled scanner Lambda function."
  value       = aws_lambda_function.scanner.function_name
}

output "scanner_lambda_function_arn" {
  description = "ARN of the scheduled scanner Lambda function."
  value       = aws_lambda_function.scanner.arn
}

output "scanner_schedule_expression" {
  description = "The EventBridge schedule expression currently configured."
  value       = aws_cloudwatch_event_rule.scanner_schedule.schedule_expression
}

output "config_rule_names" {
  description = "Names of the deployed AWS Config custom rules (empty if enable_config_rules = false)."
  value = var.enable_config_rules ? [
    aws_config_config_rule.ebs_encryption[0].name,
    aws_config_config_rule.security_group[0].name,
    aws_config_config_rule.required_tags[0].name,
  ] : []
}

output "manual_invoke_command" {
  description = "AWS CLI command to manually trigger a scan immediately (useful right after deploying)."
  value       = "aws lambda invoke --function-name ${aws_lambda_function.scanner.function_name} --payload '{}' /tmp/scan-output.json && cat /tmp/scan-output.json"
}
