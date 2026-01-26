from django.conf import settings
from django.db import models


class Friend(models.Model):
    """친구 관계 (양방향 2개 레코드로 저장)"""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="friends",
    )
    friend = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="friends_of",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "friends"
        constraints = [
            models.UniqueConstraint(fields=["user", "friend"], name="uniq_friend_pair"),
            models.CheckConstraint(
                condition=~models.Q(user=models.F("friend")),
                name="friend_no_self",
            ),
        ]
        indexes = [
            models.Index(fields=["user", "created_at"], name="friend_user_created_idx"),
        ]

    def __str__(self):
        return f"{self.user_id} -> {self.friend_id}"


class FriendRequest(models.Model):
    """친구 요청 (단방향)"""

    from_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="friend_requests_sent",
    )
    to_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="friend_requests_received",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "friend_requests"
        constraints = [
            models.UniqueConstraint(
                fields=["from_user", "to_user"], name="uniq_friend_request"
            ),
            models.CheckConstraint(
                condition=~models.Q(from_user=models.F("to_user")),
                name="friend_request_no_self",
            ),
        ]
        indexes = [
            models.Index(fields=["to_user", "created_at"], name="friend_request_to_idx"),
            models.Index(fields=["from_user", "created_at"], name="friend_request_from_idx"),
        ]

    def __str__(self):
        return f"{self.from_user_id} -> {self.to_user_id}"
