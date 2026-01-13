"""인증 토큰 통합 모델"""

import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


class AuthTokenManager(models.Manager):
    """인증 토큰 매니저"""

    def delete_expired(self, token_type: str | None = None):
        """만료된 토큰 삭제 (만료 시간이 지났거나 사용된 토큰)

        Args:
            token_type: 특정 타입만 삭제하려면 지정 (None이면 전체)
        """
        now = timezone.now()
        queryset = self.filter(models.Q(expires_at__lt=now) | models.Q(is_used=True))
        if token_type:
            queryset = queryset.filter(token_type=token_type)
        deleted_count, _ = queryset.delete()
        return deleted_count

    def email_verification(self):
        """이메일 인증 토큰만 필터링"""
        return self.filter(token_type=AuthToken.TokenType.EMAIL_VERIFICATION)

    def password_reset(self):
        """비밀번호 재설정 토큰만 필터링"""
        return self.filter(token_type=AuthToken.TokenType.PASSWORD_RESET)


class AuthToken(models.Model):
    """통합 인증 토큰 (이메일 인증, 비밀번호 재설정)"""

    class TokenType(models.TextChoices):
        EMAIL_VERIFICATION = "email_verification", "이메일 인증"
        PASSWORD_RESET = "password_reset", "비밀번호 재설정"

    objects = AuthTokenManager()

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="auth_tokens",
        help_text="연결된 사용자",
    )

    token_type = models.CharField(
        max_length=20,
        choices=TokenType.choices,
        help_text="토큰 타입",
    )

    token = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="인증 토큰",
    )

    # 이메일 변경 요청 시에만 사용
    new_email = models.EmailField(
        null=True,
        blank=True,
        help_text="이메일 변경 요청 시 새 이메일",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="토큰 만료 시간")

    is_used = models.BooleanField(default=False, help_text="사용 여부")
    used_at = models.DateTimeField(null=True, blank=True, help_text="사용 시간")

    class Meta:
        db_table = "auth_tokens"
        ordering = ["-created_at"]
        verbose_name = "인증 토큰"
        verbose_name_plural = "인증 토큰"
        indexes = [
            models.Index(fields=["user", "token_type", "is_used"], name="idx_user_type_used"),
            models.Index(fields=["expires_at"], name="idx_token_expires_at"),
        ]

    def __str__(self):
        return f"[{self.get_token_type_display()}] {self.user.email} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired

    @classmethod
    def generate_token(cls):
        return secrets.token_urlsafe(48)
