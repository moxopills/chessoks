"""이메일 인증 토큰 모델"""

import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


class EmailVerificationTokenManager(models.Manager):
    """이메일 인증 토큰 매니저"""

    def delete_expired(self):
        """만료된 토큰 삭제 (만료 시간이 지났거나 사용된 토큰)"""
        now = timezone.now()
        deleted_count, _ = self.filter(
            models.Q(expires_at__lt=now) | models.Q(is_used=True)
        ).delete()
        return deleted_count


class EmailVerificationToken(models.Model):
    """이메일 인증 토큰"""

    objects = EmailVerificationTokenManager()

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_verification_tokens",
        help_text="연결된 사용자",
    )

    token = models.CharField(
        max_length=64, unique=True, db_index=True, help_text="이메일 인증 토큰"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="토큰 만료 시간")

    is_used = models.BooleanField(default=False, help_text="사용 여부")
    used_at = models.DateTimeField(null=True, blank=True, help_text="사용 시간")

    class Meta:
        db_table = "email_verification_tokens"
        ordering = ["-created_at"]
        verbose_name = "이메일 인증 토큰"
        verbose_name_plural = "이메일 인증 토큰"
        indexes = [
            models.Index(fields=["user", "is_used"], name="idx_user_is_used"),
            models.Index(fields=["expires_at"], name="idx_expires_at"),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired

    @classmethod
    def generate_token(cls):
        return secrets.token_urlsafe(48)
