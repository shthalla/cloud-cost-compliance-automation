###############################################################################
# lambda_package.tf
#
# Builds the Lambda deployment zip directly from the repo's src/ directory
# using Terraform's archive_file data source -- no separate build step
# required for the pure-Python application code. boto3 is NOT bundled (the
# Lambda Python runtime already provides it); see scripts/build_lambda_package.sh
# if you need a pinned boto3 version instead of the runtime's.
###############################################################################

data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/../../src"
  output_path = "${path.module}/.build/lambda_package.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}
