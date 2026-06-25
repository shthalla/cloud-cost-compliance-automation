"""
formatters.py
-------------
Turns a ScanResult into the two formats consumers care about:
  * A plain-text summary suitable for SNS (email/Slack-via-subscription/SMS), and
  * A full JSON document suitable for archiving to S3 / ingesting into a
    dashboard.

Kept separate from the SNS publishing code so formatting logic is trivially
unit-testable without touching boto3 at all.
"""

from collections import defaultdict
from typing import Dict, List

from cloud_compliance_scanner.models import Finding, ScanResult, Severity

_SEVERITY_EMOJI = {
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟠",
    Severity.LOW: "🟡",
}


def filter_by_min_severity(findings: List[Finding], min_severity: str) -> List[Finding]:
    """Drop findings below the configured minimum severity for notification purposes."""
    try:
        threshold = Severity.rank(Severity(min_severity.upper()))
    except ValueError:
        threshold = Severity.rank(Severity.LOW)
    return [f for f in findings if Severity.rank(f.severity) >= threshold]


def build_text_summary(result: ScanResult, account_id: str = None) -> str:
    """Build the plain-text SNS message body."""
    lines: List[str] = []
    lines.append("Cloud Cost & Compliance Scan Report")
    lines.append("=" * 40)
    if account_id:
        lines.append(f"Account: {account_id}")
    lines.append(f"Scan window: {result.scan_started_at} -> {result.scan_finished_at}")
    lines.append(f"Regions scanned: {', '.join(result.regions_scanned)}")
    lines.append(f"Total findings: {len(result.findings)}")
    lines.append(
        f"Estimated potential monthly savings: ${result.total_estimated_monthly_savings_usd:,.2f}"
    )
    lines.append("")

    if not result.findings:
        lines.append("No idle or unused resources detected. Nice and tidy!")
    else:
        by_type: Dict[str, List[Finding]] = defaultdict(list)
        for f in result.findings:
            by_type[f.resource_type.value].append(f)

        for resource_type, findings in sorted(by_type.items()):
            subtotal = sum(f.estimated_monthly_cost_usd for f in findings)
            lines.append(
                f"--- {resource_type} ({len(findings)} findings, ~${subtotal:,.2f}/mo) ---"
            )
            # Highest severity / cost first
            for f in sorted(
                findings,
                key=lambda x: (Severity.rank(x.severity), x.estimated_monthly_cost_usd),
                reverse=True,
            ):
                emoji = _SEVERITY_EMOJI.get(f.severity, "")
                lines.append(
                    f"  {emoji} [{f.severity.value}] {f.resource_id} ({f.region}) "
                    f"~${f.estimated_monthly_cost_usd:,.2f}/mo -- {f.reason}"
                )
            lines.append("")

    if result.errors:
        lines.append("--- Scan errors (these regions/scanners may have incomplete data) ---")
        for err in result.errors:
            lines.append(f"  - {err['scanner']} in {err['region']}: {err['error']}")
        lines.append("")

    return "\n".join(lines)


def build_subject(result: ScanResult) -> str:
    """SNS subject line, kept under SNS's 100-char limit."""
    count = len(result.findings)
    savings = result.total_estimated_monthly_savings_usd
    subject = f"Cloud Scan: {count} findings, ~${savings:,.0f}/mo potential savings"
    return subject[:100]
