from django.conf import settings
from django.db import models

from .lobby_message import LobbyMessage


class LobbyMessageReaction(models.Model):
    """로비 메시지 반응"""

    message = models.ForeignKey(
        LobbyMessage,
        on_delete=models.CASCADE,
        related_name="reactions",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="lobby_message_reactions",
    )
    emoji = models.CharField(max_length=8)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "lobby_message_reactions"
        verbose_name = "로비 메시지 반응"
        verbose_name_plural = "로비 메시지 반응"
        constraints = [
            models.UniqueConstraint(
                fields=["message", "user", "emoji"],
                name="uniq_lobby_message_reaction",
            )
        ]
        indexes = [
            models.Index(fields=["message", "emoji"], name="lobby_react_msg_emoji_idx"),
            models.Index(fields=["user", "-created_at"], name="lobby_react_user_created_idx"),
        ]
