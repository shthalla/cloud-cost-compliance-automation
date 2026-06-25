#!/usr/bin/env bash
#
# build_lambda_package.sh
# -------------------------
# Builds the Lambda deployment zip from src/, for use with the CloudFormation
# deployment path (or for manually updating a Lambda function's code without
# Terraform). Terraform's own deployment (infrastructure/terraform) builds
# this automatically via the archive_file data source and does NOT need this
# script -- it's provided for CloudFormation users and manual workflows.
#
# Output: dist/lambda_package.zip (repo-root-relative)
#
# Usage:
#   ./scripts/build_lambda_package.sh
#   ./scripts/build_lambda_package.sh --with-boto3   # bundle a pinned boto3
#                                                      # instead of relying on
#                                                      # the Lambda runtime's

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/.build/lambda_package"
DIST_DIR="${REPO_ROOT}/dist"
OUTPUT_ZIP="${DIST_DIR}/lambda_package.zip"

WITH_BOTO3=false
if [[ "${1:-}" == "--with-boto3" ]]; then
  WITH_BOTO3=true
fi

echo "==> Cleaning previous build artifacts"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}" "${DIST_DIR}"

echo "==> Copying application source"
cp -r "${REPO_ROOT}/src/cloud_compliance_scanner" "${BUILD_DIR}/"

# Strip __pycache__ / .pyc cruft so the zip stays small and deterministic
find "${BUILD_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -type f -name "*.pyc" -delete

if [[ "${WITH_BOTO3}" == "true" ]]; then
  echo "==> Bundling pinned boto3/botocore (per requirements.txt)"
  pip install -r "${REPO_ROOT}/requirements.txt" --target "${BUILD_DIR}" --break-system-packages
else
  echo "==> Skipping boto3 bundling (Lambda's Python runtime provides it)"
fi

echo "==> Creating zip: ${OUTPUT_ZIP}"
rm -f "${OUTPUT_ZIP}"
( cd "${BUILD_DIR}" && zip -r -q "${OUTPUT_ZIP}" . -x "*.pyc" )

echo "==> Done. Package size:"
du -h "${OUTPUT_ZIP}"

echo ""
echo "Next steps for CloudFormation deployment:"
echo "  aws s3 cp ${OUTPUT_ZIP} s3://<your-deploy-bucket>/cloud-compliance-scanner/lambda_package.zip"
