from django.urls import path

from apps.notifications.views import (
    NotificationListView,
    NotificationReadView,
    NotificationUnreadView,
)

app_name = "notifications"

urlpatterns = [
    path("", NotificationListView.as_view(), name="notification-list"),
    path("read/", NotificationReadView.as_view(), name="notification-read"),
    path("unread/", NotificationUnreadView.as_view(), name="notification-unread"),
]
