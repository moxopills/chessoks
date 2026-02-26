from django.urls import path

from apps.notifications.views import (
    NotificationListView,
    NotificationReadView,
    NotificationUnreadView,
    WebPushSubscribeView,
    WebPushUnsubscribeView,
)

app_name = "notifications"

urlpatterns = [
    path("", NotificationListView.as_view(), name="notification-list"),
    path("read/", NotificationReadView.as_view(), name="notification-read"),
    path("unread/", NotificationUnreadView.as_view(), name="notification-unread"),
    path("push/subscribe/", WebPushSubscribeView.as_view(), name="push-subscribe"),
    path("push/unsubscribe/", WebPushUnsubscribeView.as_view(), name="push-unsubscribe"),
]
