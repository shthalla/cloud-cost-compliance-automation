"""
cloudwatch_helper.py
---------------------
Small helper around CloudWatch GetMetricStatistics / get_metric_data so
scanners don't repeat boilerplate for building time windows and parsing
datapoints.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cloud_compliance_scanner.utils.logging_utils import get_logger

logger = get_logger(__name__)


def get_average_metric(
    cloudwatch_client,
    namespace: str,
    metric_name: str,
    dimensions: List[dict],
    lookback_days: int,
    stat: str = "Average",
    period_seconds: int = 3600,
) -> Optional[float]:
    """
    Return the average of a CloudWatch metric over the lookback window,
    or None if there are no datapoints (e.g. brand-new resource with no
    metric history yet -- callers should treat None as "not enough data,
    don't flag").
    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)

    try:
        response = cloudwatch_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time,
            EndTime=end_time,
            Period=period_seconds,
            Statistics=[stat],
        )
    except Exception as exc:  # noqa: BLE001 - we want to degrade gracefully
        logger.warning(
            "cloudwatch_metric_fetch_failed",
            extra={
                "extra_fields": {
                    "namespace": namespace,
                    "metric_name": metric_name,
                    "dimensions": dimensions,
                    "error": str(exc),
                }
            },
        )
        return None

    datapoints = response.get("Datapoints", [])
    if not datapoints:
        return None

    values = [dp[stat] for dp in datapoints if stat in dp]
    if not values:
        return None

    return sum(values) / len(values)


def get_sum_metric(
    cloudwatch_client,
    namespace: str,
    metric_name: str,
    dimensions: List[dict],
    lookback_days: int,
    period_seconds: int = 86400,
) -> Optional[float]:
    """Sum a metric (e.g. total RequestCount) over the lookback window."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)

    try:
        response = cloudwatch_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time,
            EndTime=end_time,
            Period=period_seconds,
            Statistics=["Sum"],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "cloudwatch_metric_fetch_failed",
            extra={
                "extra_fields": {
                    "namespace": namespace,
                    "metric_name": metric_name,
                    "dimensions": dimensions,
                    "error": str(exc),
                }
            },
        )
        return None

    datapoints = response.get("Datapoints", [])
    if not datapoints:
        return None

    return sum(dp.get("Sum", 0) for dp in datapoints)
