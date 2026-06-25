# CloudFormation Deployment (Alternative to Terraform)

This directory provides a CloudFormation alternative to the Terraform stack in
`infrastructure/terraform/`. Use this if your organization standardizes on
CloudFormation/CDK rather than Terraform. **Functionally equivalent** to the
Terraform version: same Lambda functions, same SNS topic, same S3 bucket,
same EventBridge schedule, same three AWS Config rules.

## Prerequisites

1. Build the Lambda deployment package first:
   ```bash
   cd ../..  # repo root
   ./scripts/build_lambda_package.sh
   ```
   This produces `dist/lambda_package.zip`.

2. Upload it to an S3 bucket CloudFormation can read from (CloudFormation
   cannot deploy a local zip directly the way Terraform's `archive_file` +
   inline upload can):
   ```bash
   aws s3 mb s3://my-cfn-deploy-bucket-12345 --region us-east-1   # if needed
   aws s3 cp dist/lambda_package.zip s3://my-cfn-deploy-bucket-12345/cloud-compliance-scanner/lambda_package.zip
   ```

## Deploy

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name cloud-compliance-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      LambdaCodeBucket=my-cfn-deploy-bucket-12345 \
      LambdaCodeKey=cloud-compliance-scanner/lambda_package.zip \
      NotificationEmail=you@example.com \
      ScanRegions=us-east-1,us-west-2 \
      ScheduleExpression="cron(0 8 * * ? *)" \
      EnableConfigRules=true
```

## Updating after a code change

Re-run the build script, re-upload the zip to the same S3 key, then either:
* Re-run the same `aws cloudformation deploy` command (CloudFormation detects
  the new `LambdaCodeS3ObjectVersion` if your bucket has versioning enabled —
  recommended), or
* Manually update each function with:
  ```bash
  aws lambda update-function-code --function-name cloud-compliance-scanner-prod-scanner \
      --s3-bucket my-cfn-deploy-bucket-12345 --s3-key cloud-compliance-scanner/lambda_package.zip
  ```

## Tear down

```bash
aws cloudformation delete-stack --stack-name cloud-compliance-scanner
```

Note: the S3 reports bucket has `DeletionPolicy: Retain` by default (see
`template.yaml`) so historical reports aren't accidentally destroyed when you
delete the stack. Delete it manually once you've confirmed you don't need the
archived reports.
