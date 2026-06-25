###############################################################################
# variables.tf
#
# All inputs needed to deploy the scanner + Config rules stack. Sensible
# defaults are provided everywhere reasonable, but review notification_email
# and scan_regions before applying to a real account.
###############################################################################

variable "aws_region" {
  description = "AWS region to deploy the Lambda functions, SNS topic, and Config rules into. Note: this is the *control plane* region; the scanner itself can scan additional regions via scan_regions."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short name used as a prefix for all created resources (Lambda functions, IAM roles, SNS topic, S3 bucket, etc.)."
  type        = string
  default     = "cloud-compliance-scanner"
}

variable "environment" {
  description = "Environment tag applied to all resources (e.g. dev, staging, prod)."
  type        = string
  default     = "prod"
}

variable "scan_regions" {
  description = "Comma-separated list of AWS regions the scanner Lambda should scan for idle/unused resources. Defaults to just the deployment region."
  type        = list(string)
  default     = ["us-east-1"]
}

variable "schedule_expression" {
  description = "EventBridge schedule expression for how often the scan runs. Examples: 'rate(1 day)', 'rate(12 hours)', 'cron(0 8 * * ? *)' (daily at 08:00 UTC)."
  type        = string
  default     = "cron(0 8 * * ? *)"
}

variable "notification_email" {
  description = "Email address to subscribe to the SNS findings topic. Leave empty string to skip creating an email subscription (e.g. if you'll subscribe Slack/another Lambda/SQS manually or via the notification_endpoints variable)."
  type        = string
  default     = ""
}

variable "notification_endpoints" {
  description = "Additional SNS subscriptions beyond email, e.g. for Slack-via-Lambda or SQS fan-out. Each entry: { protocol = \"lambda\"|\"sqs\"|\"https\"|..., endpoint = \"arn or url\" }."
  type = list(object({
    protocol = string
    endpoint = string
  }))
  default = []
}

variable "min_severity_to_notify" {
  description = "Minimum finding severity that triggers an SNS notification: LOW, MEDIUM, or HIGH. Findings below this are still archived to S3 but won't generate a notification."
  type        = string
  default     = "LOW"
}

# --- Scanner threshold tuning (all optional; defaults are reasonable) ------

variable "ec2_idle_cpu_threshold_pct" {
  description = "Average CPU% below which a running EC2 instance is considered idle."
  type        = number
  default     = 5.0
}

variable "ec2_idle_lookback_days" {
  description = "Number of days of CloudWatch history to average over when judging EC2 idleness."
  type        = number
  default     = 14
}

variable "ebs_unattached_grace_days" {
  description = "Number of days an EBS volume must be unattached before it's flagged (avoids flagging volumes mid-migration)."
  type        = number
  default     = 7
}

variable "snapshot_max_age_days" {
  description = "Age in days above which an EBS snapshot is flagged as stale."
  type        = number
  default     = 90
}

variable "elb_idle_lookback_days" {
  description = "Number of days of CloudWatch history to sum over when judging load balancer idleness."
  type        = number
  default     = 14
}

variable "elb_idle_request_threshold" {
  description = "Total requests/flows below which a load balancer is considered idle over the lookback window."
  type        = number
  default     = 1
}

variable "exclusion_tag_keys" {
  description = "Tag KEYS (any value) that exempt a resource from being flagged, e.g. for known-good long-idle assets."
  type        = list(string)
  default     = ["doNotDelete", "scanner:ignore"]
}

variable "lambda_memory_mb" {
  description = "Memory (MB) allocated to the scanner Lambda. Increase if scanning many regions/large accounts and seeing timeouts."
  type        = number
  default     = 512
}

variable "lambda_timeout_seconds" {
  description = "Timeout (seconds) for the scanner Lambda. Increase for accounts with many resources/regions."
  type        = number
  default     = 300
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period for all Lambda function log groups."
  type        = number
  default     = 30
}

# --- AWS Config rule toggles -------------------------------------------------

variable "enable_config_rules" {
  description = "Whether to deploy the AWS Config custom rules (continuous compliance drift detection). Requires AWS Config to already be enabled/recording in this account+region -- set to false if you don't use AWS Config or want to deploy it separately."
  type        = bool
  default     = true
}

variable "required_tag_keys" {
  description = "Tag keys required on scanned resources for the required-tags Config rule."
  type        = list(string)
  default     = ["Environment", "Owner"]
}

variable "sensitive_security_group_ports" {
  description = "Ports considered sensitive for the open-security-group Config rule (flagged if open to 0.0.0.0/0)."
  type        = list(number)
  default     = [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200]
}

variable "tags" {
  description = "Common tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}
