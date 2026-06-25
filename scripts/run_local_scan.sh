#!/usr/bin/env bash
#
# run_local_scan.sh
# -------------------
# Convenience wrapper to run a scan locally using your current AWS CLI
# credentials, in dry-run mode by default (no SNS publish, no S3 write --
# just prints the report). Useful for testing thresholds before deploying.
#
# Usage:
#   ./scripts/run_local_scan.sh                     # dry-run, default region
#   ./scripts/run_local_scan.sh --regions us-east-1,eu-west-1
#   AWS_PROFILE=myprofile ./scripts/run_local_scan.sh --live   # actually publish/archive

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LIVE=false
EXTRA_ARGS=()

for arg in "$@"; do
  if [[ "$arg" == "--live" ]]; then
    LIVE=true
  else
    EXTRA_ARGS+=("$arg")
  fi
done

cd "${REPO_ROOT}"

if [[ "${LIVE}" == "true" ]]; then
  echo "==> Running LIVE scan (will publish to SNS / archive to S3 if configured)"
  python3 -m cloud_compliance_scanner.cli "${EXTRA_ARGS[@]}"
else
  echo "==> Running DRY-RUN scan (no SNS publish, no S3 write)"
  python3 -m cloud_compliance_scanner.cli --dry-run "${EXTRA_ARGS[@]}"
fi
