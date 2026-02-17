"""게임 초대 모델"""

from django.conf import settings
from django.db import models


class GameInvite(models.Model):
    """게임 초대"""

    STATUS_CHOICES = [
        ("pending", "대기"),
        ("accepted", "수락"),
        ("declined", "거절"),
        ("expired", "만료"),
    ]

    from_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sent_invites",
        help_text="초대를 보낸 사용자",
    )

    to_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="received_invites",
        help_text="초대를 받은 사용자",
    )

    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default="pending",
    )

    time_limit = models.IntegerField(
        default=10,
        help_text="게임 시간 제한 (분)",
    )

    room = models.ForeignKey(
        "chess.Room",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="invites",
        help_text="수락 시 생성된 방",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "game_invites"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["to_user", "status", "-created_at"]),
            models.Index(fields=["from_user", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.from_user} -> {self.to_user} ({self.status})"
