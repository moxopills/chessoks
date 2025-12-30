from django.conf import settings
from django.db import models


class SocialUser(models.Model):
    """소셜 로그인 계정 모델 - OAuth 연동"""

    PROVIDER_CHOICES = [
        ("google", "Google"),
        ("github", "GitHub"),
        ("kakao", "Kakao"),
        ("naver", "Naver"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="social_users",
        help_text="연결된 사용자",
    )

    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES, help_text="OAuth 제공자")

    provider_user_id = models.CharField(max_length=255, help_text="제공자의 사용자 ID")

    extra_data = models.JSONField(
        default=dict, blank=True, help_text="추가 데이터 (이메일, 프로필 등)"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "social_users"
        verbose_name = "소셜 계정"
        verbose_name_plural = "소셜 계정"
        unique_together = [["provider", "provider_user_id"]]
        indexes = [
            models.Index(fields=["user", "provider"]),
            models.Index(fields=["provider", "provider_user_id"]),
        ]

    def __str__(self):
        return f"{self.user.nickname} - {self.get_provider_display()}"
