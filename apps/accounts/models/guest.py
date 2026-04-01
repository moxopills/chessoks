"""비회원 게스트 세션 모델"""

from django.db import models


class GuestSession(models.Model):
    """비회원 게스트 세션"""

    token = models.CharField(max_length=64, unique=True, db_index=True)
    nickname = models.CharField(max_length=20)
    display_name = models.CharField(max_length=30)  # "[게스트] 닉네임" 형태
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    last_activity = models.DateTimeField(auto_now=True)
    # 게임 참여용 임시 User (필요 시 생성)
    user = models.OneToOneField(
        "accounts.User",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="guest_session",
    )

    class Meta:
        indexes = [
            models.Index(fields=["expires_at"]),
            models.Index(fields=["token"]),
        ]

    def __str__(self):
        return f"{self.display_name} ({self.token[:8]}...)"
