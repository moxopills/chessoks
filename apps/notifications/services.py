import logging

from django.db import transaction

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from rest_framework.exceptions import ValidationError

from apps.notifications.models import Notification


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
        if channel_layer is None:
            return
        payload = {
            "id": notification.id,
            "type": notification.type,
            "title": notification.title,
            "message": notification.message,
            "payload": notification.payload,
            "is_read": notification.is_read,
            "created_at": notification.created_at.isoformat(),
        }
        try:
            async_to_sync(channel_layer.group_send)(
                f"notifications_user_{notification.user_id}",
                {"type": "notification", "payload": payload},
            )
        except Exception as exc:  # pragma: no cover - best-effort push
            NotificationService.logger.warning("Notification push failed: %s", exc)
