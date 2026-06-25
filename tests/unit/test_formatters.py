"""
test_formatters.py
---------------------
Unit tests for the report formatting logic. Pure functions, no AWS needed.
"""

from cloud_compliance_scanner.models import Finding, ResourceType, ScanResult, Severity
from cloud_compliance_scanner.reporting.formatters import (
    build_subject,
    build_text_summary,
    filter_by_min_severity,
)


def _make_finding(resource_id="i-123", severity=Severity.MEDIUM, cost=10.0):
    return Finding(
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=resource_id,
        region="us-east-1",
        reason="test reason",
        severity=severity,
        estimated_monthly_cost_usd=cost,
    )


def _make_result(findings):
    return ScanResult(
        findings=findings,
        scan_started_at="2026-01-01T00:00:00+00:00",
        scan_finished_at="2026-01-01T00:05:00+00:00",
        regions_scanned=["us-east-1"],
    )


def test_filter_by_min_severity_keeps_only_high_when_threshold_high():
    findings = [
        _make_finding("i-low", Severity.LOW),
        _make_finding("i-med", Severity.MEDIUM),
        _make_finding("i-high", Severity.HIGH),
    ]
    filtered = filter_by_min_severity(findings, "HIGH")
    assert [f.resource_id for f in filtered] == ["i-high"]


def test_filter_by_min_severity_keeps_all_when_threshold_low():
    findings = [
        _make_finding("i-low", Severity.LOW),
        _make_finding("i-med", Severity.MEDIUM),
        _make_finding("i-high", Severity.HIGH),
    ]
    filtered = filter_by_min_severity(findings, "LOW")
    assert len(filtered) == 3


def test_build_text_summary_includes_totals_and_findings():
    findings = [_make_finding("i-abc", Severity.HIGH, cost=42.50)]
    result = _make_result(findings)

    summary = build_text_summary(result, account_id="123456789012")

    assert "123456789012" in summary
    assert "i-abc" in summary
    assert "42.50" in summary
    assert "EC2_INSTANCE" in summary


def test_build_text_summary_handles_empty_findings():
    result = _make_result([])
    summary = build_text_summary(result)
    assert "No idle or unused resources detected" in summary


def test_build_subject_is_under_100_chars():
    findings = [_make_finding(f"i-{i}", Severity.HIGH, cost=100.0) for i in range(5)]
    result = _make_result(findings)
    subject = build_subject(result)
    assert len(subject) <= 100
    assert "5 findings" in subject
