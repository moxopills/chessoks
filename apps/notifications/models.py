from django.conf import settings
from django.db import models


class Notification(models.Model):
    """알림 모델"""

    TYPE_CHOICES = [
        ("friend_request", "친구 요청"),
        ("friend_accept", "친구 수락"),
        ("match_found", "매칭 완료"),
        ("room_event", "방 이벤트"),
        ("rematch", "리매치"),
        ("game_invite", "게임 초대"),
        ("game_invite_declined", "초대 거절"),
        ("game_result", "게임 결과"),
        ("rating_change", "레이팅 변동"),
        ("tier_promotion", "티어 승격"),
        ("season_end", "시즌 종료"),
        ("season_reward", "시즌 보상"),
        ("direct_message", "1:1 메시지"),
        ("admin_notice", "공지"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    title = models.CharField(max_length=100)
    message = models.CharField(max_length=255)
    payload = models.JSONField(default=dict, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "notifications"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "is_read", "created_at"], name="notif_user_read_idx"),
        ]

    def __str__(self):
        return f"{self.user_id} - {self.type}"


class WebPushSubscription(models.Model):
    """웹 푸시 구독 정보"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="web_push_subscriptions",
    )
    endpoint = models.TextField(unique=True)
    p256dh = models.TextField()
    auth = models.TextField()
    user_agent = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "web_push_subscriptions"
        indexes = [
            models.Index(fields=["user", "is_active"], name="push_user_active_idx"),
        ]

    def __str__(self):
        return f"{self.user_id} - {self.endpoint[:40]}"
