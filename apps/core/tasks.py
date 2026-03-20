"""운영 모니터링 태스크."""

import logging

from celery import shared_task

from apps.core.ops import collect_health_snapshot, collect_runtime_metrics, summarize_health

logger = logging.getLogger(__name__)


@shared_task
def emit_runtime_health_snapshot() -> None:
    snapshot = collect_health_snapshot()
    is_ready, checks = summarize_health(snapshot)
    metrics = collect_runtime_metrics()
    celery_metrics = metrics.get("queues", {}).get("celery", {})

    logger.info(
        "Runtime health snapshot",
        extra={
            "event": "runtime_snapshot",
            "component": "ops",
            "reason": "scheduled_monitor",
            "queue_name": celery_metrics.get("queue_name"),
            "queue_depth": celery_metrics.get("queue_depth"),
            "subscription_count": (
                metrics.get("notifications", {}).get("push_subscriptions_active")
            ),
        },
    )

    if not is_ready:
        logger.warning(
            "Runtime health degraded",
            extra={
                "event": "runtime_health_degraded",
                "component": "ops",
                "reason": str(checks),
                "queue_name": celery_metrics.get("queue_name"),
                "queue_depth": celery_metrics.get("queue_depth"),
                "subscription_count": (
                    metrics.get("notifications", {}).get("push_subscriptions_active")
                ),
            },
        )
