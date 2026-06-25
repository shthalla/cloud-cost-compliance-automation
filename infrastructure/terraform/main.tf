###############################################################################
# main.tf
#
# Shared locals/data sources used across the rest of the Terraform config.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.tags
  )

  name_prefix = "${var.project_name}-${var.environment}"
}
