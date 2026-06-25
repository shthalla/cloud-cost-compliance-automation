"""
cloud_compliance_scanner
=========================

Python/Boto3 automation that scans an AWS account for idle and unused
resources (EC2, EBS, Elastic IPs, Load Balancers, snapshots), reports
findings on a schedule via Amazon SNS, and exposes AWS Config Lambda
evaluators for continuous compliance drift detection.

This package is designed to run either:
  * Locally / in CI (for testing and ad-hoc audits), or
  * Inside AWS Lambda (scheduled scans + Config rule evaluations).
"""

__version__ = "1.0.0"
