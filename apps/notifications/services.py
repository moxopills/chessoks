import json
import logging

from django.conf import settings
from django.core.cache import cache
from django.db import transaction

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from rest_framework.exceptions import ValidationError

from apps.notifications.models import Notification, WebPushSubscription


class NotificationService:
    """알림 서비스"""

    logger = logging.getLogger(__name__)
    SOCKET_GROUP_PREFIX = "notifications_user_"
    LIST_CACHE_TTL = 30
    CACHE_VERSION_PREFIX = "notifications_version:"
    LIST_CACHE_PREFIX = "notifications:list:"
    UNREAD_COUNT_CACHE_PREFIX = "notifications:unread:"

    @classmethod
    def _version_key(cls, user_id: int) -> str:
        return f"{cls.CACHE_VERSION_PREFIX}{user_id}"

    @classmethod
    def _list_cache_key(cls, user_id: int, *, limit: int, offset: int, no_count: bool) -> str:
        version = cls._get_cache_version(user_id)
        return f"{cls.LIST_CACHE_PREFIX}{user_id}:v{version}:l{limit}:o{offset}:n{int(no_count)}"

    @classmethod
    def _get_cache_version(cls, user_id: int) -> int:
        version = cache.get(cls._version_key(user_id))
        return version if version is not None else 0

    @classmethod
    def _unread_count_cache_key(cls, user_id: int) -> str:
        version = cls._get_cache_version(user_id)
        return f"{cls.UNREAD_COUNT_CACHE_PREFIX}{user_id}:v{version}"

    @classmethod
    def _invalidate_user_cache(cls, user_id: int) -> None:
        version_key = cls._version_key(user_id)
        try:
            cache.incr(version_key)
        except ValueError:
            cache.set(version_key, 1, None)

    @staticmethod
    def list_notifications(
        user, *, limit: int, offset: int, no_count: bool = False
    ) -> tuple[int, list[Notification]]:
        cache_key = NotificationService._list_cache_key(
            user.id,
            limit=limit,
            offset=offset,
            no_count=no_count,
        )
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        queryset = Notification.objects.filter(user=user).only(
            "id",
            "type",
            "title",
            "message",
            "payload",
            "is_read",
            "created_at",
        )
        items = list(queryset.order_by("-created_at")[offset : offset + limit])
        result = (len(items), items) if no_count else (queryset.count(), items)
        cache.set(cache_key, result, NotificationService.LIST_CACHE_TTL)
        return result

    @staticmethod
    def count_unread(user) -> int:
        cache_key = NotificationService._unread_count_cache_key(user.id)
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        count = Notification.objects.filter(user=user, is_read=False).count()
        cache.set(cache_key, count, NotificationService.LIST_CACHE_TTL)
        return count

    @staticmethod
    def mark_read(user, ids: list[int]) -> int:
        if not ids:
            raise ValidationError({"ids": "ids는 비어있을 수 없습니다."})
        with transaction.atomic():
            updated = Notification.objects.filter(user=user, id__in=ids, is_read=False).update(
                is_read=True
            )
        if updated:
            NotificationService._invalidate_user_cache(user.id)
        return updated

    @staticmethod
    def create_notification(
        user,
        *,
        type: str,
        title: str,
        message: str,
        payload: dict | None = None,
        push: bool = True,
    ) -> Notification:
        notification = Notification.objects.create(
            user=user,
            type=type,
            title=title,
            message=message,
            payload=payload or {},
        )
        NotificationService._invalidate_user_cache(user.id)
        if push:
            NotificationService._push(notification)
        return notification

    @staticmethod
    def bulk_create_notifications(
        rows: list[dict],
        *,
        push: bool = False,
    ) -> list[Notification]:
        if not rows:
            return []
        notifications = [
            Notification(
                user=row["user"],
                type=row["type"],
                title=row["title"],
                message=row["message"],
                payload=row.get("payload") or {},
            )
            for row in rows
        ]
        created = Notification.objects.bulk_create(notifications)
        for user_id in {item.user_id for item in created if item.user_id}:
            NotificationService._invalidate_user_cache(user_id)
        if push:
            NotificationService._push_bulk(created)
        return created

    @staticmethod
    def _push(notification: Notification) -> None:
        channel_layer = get_channel_layer()
        payload = NotificationService._serialize(notification)
        if channel_layer is not None:
            try:
                async_to_sync(channel_layer.group_send)(
                    f"{NotificationService.SOCKET_GROUP_PREFIX}{notification.user_id}",
                    {"type": "notification", "payload": payload},
                )
            except Exception as exc:  # pragma: no cover - best-effort push
                NotificationService.logger.warning("Notification socket push failed: %s", exc)
        WebPushService.send_async(notification.id)

    @staticmethod
    def _push_bulk(notifications: list[Notification]) -> None:
        if not notifications:
            return
        channel_layer = get_channel_layer()
        if channel_layer is not None:
            grouped: dict[int, list[Notification]] = {}
            for item in notifications:
                grouped.setdefault(item.user_id, []).append(item)
            for user_id, user_notifications in grouped.items():
                for item in user_notifications:
                    payload = NotificationService._serialize(item)
                    try:
                        async_to_sync(channel_layer.group_send)(
                            f"{NotificationService.SOCKET_GROUP_PREFIX}{user_id}",
                            {"type": "notification", "payload": payload},
                        )
                    except Exception as exc:  # pragma: no cover - best-effort push
                        NotificationService.logger.warning(
                            "Notification bulk socket push failed: %s", exc
                        )
        ids = [item.id for item in notifications if item.id]
        if ids:
            try:
                from apps.notifications.tasks import send_web_push_for_notifications

                send_web_push_for_notifications.delay(ids)
            except Exception as exc:
                NotificationService.logger.warning("Web push bulk dispatch failed: %s", exc)

    @staticmethod
    def _serialize(notification: Notification) -> dict:
        return {
            "id": notification.id,
            "type": notification.type,
            "title": notification.title,
            "message": notification.message,
            "payload": notification.payload,
            "is_read": notification.is_read,
            "created_at": notification.created_at.isoformat(),
        }


class WebPushService:
    """웹 푸시 구독/발송 서비스"""

    logger = logging.getLogger(__name__)
    DEFAULT_TITLE = "ChessOK"

    @staticmethod
    def send_async(notification_id: int) -> None:
        """요청 지연을 줄이기 위해 웹푸시는 Celery로 비동기 처리한다."""
        try:
            from apps.notifications.tasks import send_web_push_for_notification

            send_web_push_for_notification.delay(notification_id)
        except Exception as exc:
            WebPushService.logger.warning("Web push async dispatch failed: %s", exc)

    @staticmethod
    def subscribe(user, *, endpoint: str, p256dh: str, auth: str, user_agent: str = "") -> None:
        # 같은 사용자/브라우저(user_agent)에서 새 endpoint로 재구독 시
        # 기존 endpoint는 비활성화해 중복 푸시를 줄인다.
        if user_agent:
            WebPushSubscription.objects.filter(
                user=user,
                user_agent=user_agent,
                is_active=True,
            ).exclude(endpoint=endpoint).update(is_active=False)
        WebPushSubscription.objects.update_or_create(
            endpoint=endpoint,
            defaults={
                "user": user,
                "p256dh": p256dh,
                "auth": auth,
                "user_agent": user_agent,
                "is_active": True,
            },
        )

    @staticmethod
    def unsubscribe(user, *, endpoint: str | None = None) -> int:
        queryset = WebPushSubscription.objects.filter(user=user, is_active=True)
        if endpoint:
            queryset = queryset.filter(endpoint=endpoint)
        return queryset.update(is_active=False)

    @staticmethod
    def send(notification: Notification) -> None:
        public_key = getattr(settings, "WEB_PUSH_PUBLIC_KEY", "")
        private_key = getattr(settings, "WEB_PUSH_PRIVATE_KEY", "")
        subject = getattr(settings, "WEB_PUSH_SUBJECT", "")
        if not public_key or not private_key or not subject:
            return

        try:
            from pywebpush import WebPushException, webpush
        except Exception:
            # Optional dependency. If missing, websocket/in-app notifications still work.
            return

        payload = WebPushService._build_payload(notification)

        subscriptions = list(
            WebPushSubscription.objects.filter(user=notification.user, is_active=True).only(
                "id", "endpoint", "p256dh", "auth"
            )
        )
        for sub in subscriptions:
            try:
                webpush(
                    subscription_info={
                        "endpoint": sub.endpoint,
                        "keys": {
                            "p256dh": sub.p256dh,
                            "auth": sub.auth,
                        },
                    },
                    data=payload,
                    vapid_private_key=private_key,
                    vapid_claims={"sub": subject},
                )
            except WebPushException as exc:
                if WebPushService._should_deactivate_subscription(exc):
                    WebPushSubscription.objects.filter(id=sub.id).update(is_active=False)
                    continue
                WebPushService.logger.warning(
                    "Web push send failed (subscription=%s): %s", sub.id, exc
                )
            except Exception as exc:
                WebPushService.logger.warning(
                    "Web push send unexpected failure (subscription=%s): %s", sub.id, exc
                )

    @staticmethod
    def _target_url(notification: Notification) -> str:
        payload = notification.payload or {}
        if notification.type == "game_invite":
            invite_id = payload.get("invite_id")
            if invite_id:
                return f"/?invite_id={invite_id}"
            return "/"
        if payload.get("url"):
            return str(payload["url"])
        room_id = payload.get("room_id")
        if room_id:
            if notification.type in {"match_found", "rematch"}:
                return f"/games/{room_id}/"
            return f"/rooms/{room_id}/"
        sender_id = payload.get("sender_id")
        if notification.type == "direct_message" and sender_id:
            return f"/messages/{sender_id}/"
        return "/"

    @staticmethod
    def _build_payload(notification: Notification) -> str:
        return json.dumps(
            {
                "id": notification.id,
                "type": notification.type,
                "title": notification.title or WebPushService.DEFAULT_TITLE,
                "body": notification.message or "",
                "url": WebPushService._target_url(notification),
            },
            ensure_ascii=False,
        )

    @staticmethod
    def _should_deactivate_subscription(exc: Exception) -> bool:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        return status_code in (404, 410)
