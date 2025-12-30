"""비밀번호 재설정 토큰 모델"""

import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


class PasswordResetTokenManager(models.Manager):
    """비밀번호 재설정 토큰 매니저"""

    def delete_expired(self):
        """만료된 토큰 삭제 (만료 시간이 지났거나 사용된 토큰)"""
        now = timezone.now()
        deleted_count, _ = self.filter(
            models.Q(expires_at__lt=now) | models.Q(is_used=True)
        ).delete()
        return deleted_count


class PasswordResetToken(models.Model):
    """비밀번호 재설정 토큰"""

    objects = PasswordResetTokenManager()

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="password_reset_tokens",
        help_text="연결된 사용자",
    )

    token = models.CharField(max_length=64, unique=True, db_index=True, help_text="재설정 토큰")

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="토큰 만료 시간")

    is_used = models.BooleanField(default=False, help_text="사용 여부")
    used_at = models.DateTimeField(null=True, blank=True, help_text="사용 시간")

    class Meta:
        db_table = "password_reset_tokens"
        ordering = ["-created_at"]
        verbose_name = "비밀번호 재설정 토큰"
        verbose_name_plural = "비밀번호 재설정 토큰"

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
