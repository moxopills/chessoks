from django.conf import settings
from django.db import models


class LobbyMessage(models.Model):
    """로비 채팅 메시지"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="lobby_messages",
    )
    message = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "lobby_messages"
        verbose_name = "로비 메시지"
        verbose_name_plural = "로비 메시지"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at"], name="lobby_msg_created_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.user.nickname}: {self.message[:20]}"
