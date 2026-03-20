"""운영성/헬스체크 보조 유틸."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.utils import timezone

from channels.layers import get_channel_layer

from apps.chess.models import Game, Room
from apps.notifications.models import Notification, WebPushSubscription


def _check_payload(
    status: str,
    *,
    required: bool = True,
    **details: Any,
) -> dict[str, Any]:
    payload = {"status": status, "required": required}
    payload.update(details)
    return payload


def check_database() -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return _check_payload("ok", duration_ms=duration_ms)
    except Exception as exc:
        return _check_payload("error", reason=str(exc))


def check_cache_backend() -> dict[str, Any]:
    cache_key = "ops:health:cache"
    started = time.perf_counter()
    try:
        cache.set(cache_key, "ok", 10)
        cached_value = cache.get(cache_key)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        if cached_value != "ok":
            return _check_payload("error", reason="cache round-trip mismatch")
        return _check_payload("ok", duration_ms=duration_ms)
    except Exception as exc:
        return _check_payload("error", reason=str(exc))


def check_channel_layer() -> dict[str, Any]:
    try:
        backend = settings.CHANNEL_LAYERS["default"]["BACKEND"]
        layer = get_channel_layer()
        if layer is None:
            return _check_payload("error", reason="channel layer unavailable", backend=backend)
        return _check_payload("ok", backend=backend)
    except Exception as exc:
        return _check_payload("error", reason=str(exc))


def check_web_push() -> dict[str, Any]:
    if not (
        getattr(settings, "WEB_PUSH_PUBLIC_KEY", "")
        and getattr(settings, "WEB_PUSH_PRIVATE_KEY", "")
        and getattr(settings, "WEB_PUSH_SUBJECT", "")
    ):
        return _check_payload("disabled", required=False, reason="web push not configured")

    try:
        active_count = WebPushSubscription.objects.filter(is_active=True).count()
        return _check_payload("ok", active_subscriptions=active_count)
    except Exception as exc:
        return _check_payload("error", required=False, reason=str(exc))


def check_gcs() -> dict[str, Any]:
    bucket_name = getattr(settings, "GCS_BUCKET_NAME", "")
    if not bucket_name:
        return _check_payload("disabled", required=False, reason="gcs bucket not configured")

    try:
        from apps.core.gcp.uploader import GCPUploader

        client = GCPUploader.get_client()
        return _check_payload(
            "ok",
            bucket_name=bucket_name,
            client=client.__class__.__name__,
        )
    except Exception as exc:
        return _check_payload("error", required=False, reason=str(exc), bucket_name=bucket_name)


def check_celery_broker() -> dict[str, Any]:
    if getattr(settings, "CELERY_TASK_ALWAYS_EAGER", False):
        return _check_payload("disabled", required=False, reason="celery eager mode")

    broker_url = getattr(settings, "CELERY_BROKER_URL", "")
    if not broker_url:
        return _check_payload("disabled", required=False, reason="broker url not configured")

    parsed = urlparse(broker_url)
    queue_name = getattr(settings, "CELERY_TASK_DEFAULT_QUEUE", "celery")
    if parsed.scheme not in {"redis", "rediss"}:
        return _check_payload(
            "ok",
            required=False,
            broker_scheme=parsed.scheme or "unknown",
            queue_name=queue_name,
        )

    try:
        from redis import Redis

        started = time.perf_counter()
        redis_client = Redis.from_url(broker_url)
        redis_client.ping()
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        queue_depth = int(redis_client.llen(queue_name))
        return _check_payload(
            "ok",
            queue_name=queue_name,
            queue_depth=queue_depth,
            duration_ms=duration_ms,
        )
    except Exception as exc:
        return _check_payload("error", required=False, reason=str(exc), queue_name=queue_name)


def collect_health_snapshot() -> dict[str, dict[str, Any]]:
    return {
        "database": check_database(),
        "cache": check_cache_backend(),
        "channels": check_channel_layer(),
        "web_push": check_web_push(),
        "gcs": check_gcs(),
        "celery": check_celery_broker(),
    }


def summarize_health(snapshot: dict[str, dict[str, Any]]) -> tuple[bool, dict[str, str]]:
    checks = {name: item["status"] for name, item in snapshot.items()}
    is_ready = all(
        item["status"] == "ok" for item in snapshot.values() if item.get("required", True)
    )
    return is_ready, checks


def collect_runtime_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = {"queues": {"celery": check_celery_broker()}}

    try:
        games_queryset = Game.objects.all()
        metrics["games"] = {
            "playing": games_queryset.filter(status="playing").count(),
            "finished_today": games_queryset.filter(
                status="finished",
                finished_at__date=timezone.localdate(),
            ).count(),
        }
    except Exception as exc:
        metrics["games"] = {"status": "error", "reason": str(exc)}

    try:
        rooms_queryset = Room.objects.all()
        metrics["rooms"] = {
            "waiting": rooms_queryset.filter(status="waiting").count(),
            "playing": rooms_queryset.filter(status="playing").count(),
        }
    except Exception as exc:
        metrics["rooms"] = {"status": "error", "reason": str(exc)}

    try:
        metrics["notifications"] = {
            "unread": Notification.objects.filter(is_read=False).count(),
            "push_subscriptions_active": WebPushSubscription.objects.filter(is_active=True).count(),
        }
    except Exception as exc:
        metrics["notifications"] = {"status": "error", "reason": str(exc)}

    return metrics
