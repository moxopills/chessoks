import json
import logging

from django.conf import settings
from django.db import transaction

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from rest_framework.exceptions import ValidationError

from apps.notifications.models import Notification, WebPushSubscription


class NotificationService:
    """알림 서비스"""

    logger = logging.getLogger(__name__)

    @staticmethod
    def list_notifications(
        user, *, limit: int, offset: int, no_count: bool = False
    ) -> tuple[int, list[Notification]]:
        queryset = Notification.objects.filter(user=user).order_by("-created_at")
        items = list(queryset[offset : offset + limit])
        if no_count:
            return len(items), items
        total = queryset.count()
        return total, items

    @staticmethod
    def count_unread(user) -> int:
        return Notification.objects.filter(user=user, is_read=False).count()

    @staticmethod
    def mark_read(user, ids: list[int]) -> int:
        if not ids:
            raise ValidationError({"ids": "ids는 비어있을 수 없습니다."})
        with transaction.atomic():
            updated = Notification.objects.filter(user=user, id__in=ids, is_read=False).update(
                is_read=True
            )
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
        if push:
            NotificationService._push(notification)
        return notification

    @staticmethod
    def _push(notification: Notification) -> None:
        channel_layer = get_channel_layer()
        payload = {
            "id": notification.id,
            "type": notification.type,
            "title": notification.title,
            "message": notification.message,
            "payload": notification.payload,
            "is_read": notification.is_read,
            "created_at": notification.created_at.isoformat(),
        }
        if channel_layer is not None:
            try:
                async_to_sync(channel_layer.group_send)(
                    f"notifications_user_{notification.user_id}",
                    {"type": "notification", "payload": payload},
                )
            except Exception as exc:  # pragma: no cover - best-effort push
                NotificationService.logger.warning("Notification socket push failed: %s", exc)
        WebPushService.send_async(notification.id)


class WebPushService:
    """웹 푸시 구독/발송 서비스"""

    logger = logging.getLogger(__name__)

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

        url = WebPushService._target_url(notification)
        payload = json.dumps(
            {
                "id": notification.id,
                "type": notification.type,
                "title": notification.title or "ChessOK",
                "body": notification.message or "",
                "url": url,
            },
            ensure_ascii=False,
        )

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
                status_code = getattr(getattr(exc, "response", None), "status_code", None)
                if status_code in (404, 410):
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
