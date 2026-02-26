from celery import shared_task

from apps.notifications.models import Notification
from apps.notifications.services import WebPushService


@shared_task
def send_web_push_for_notification(notification_id: int) -> None:
    notification = Notification.objects.filter(id=notification_id).first()
    if not notification:
        return
    WebPushService.send(notification)
