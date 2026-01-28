"""회원가입 이메일 인증 토큰"""

import secrets

from django.db import models
from django.utils import timezone


class SignupEmailTokenManager(models.Manager):
    """회원가입 이메일 인증 토큰 매니저"""

    def delete_expired(self):
        """만료되었거나 사용된 토큰 삭제"""
        now = timezone.now()
        queryset = self.filter(models.Q(expires_at__lt=now) | models.Q(is_used=True))
        deleted_count, _ = queryset.delete()
        return deleted_count

    def invalidate_existing(self, email: str) -> None:
        """해당 이메일의 기존 미사용 토큰 무효화"""
        self.filter(email=email, is_used=False).update(is_used=True, used_at=timezone.now())


class SignupEmailToken(models.Model):
    """회원가입 전 이메일 인증을 위한 토큰"""

    objects = SignupEmailTokenManager()

    email = models.EmailField(help_text="인증 대상 이메일")
    token = models.CharField(max_length=64, unique=True, db_index=True, help_text="내부 토큰")
    code_hash = models.CharField(max_length=64, help_text="인증 코드 해시")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="토큰 만료 시간")
    is_used = models.BooleanField(default=False, help_text="사용 여부")
    used_at = models.DateTimeField(null=True, blank=True, help_text="사용 시간")
    attempts = models.PositiveSmallIntegerField(default=0, help_text="인증 시도 횟수")

    class Meta:
        db_table = "signup_email_tokens"
        ordering = ["-created_at"]
        verbose_name = "회원가입 이메일 토큰"
        verbose_name_plural = "회원가입 이메일 토큰"
        indexes = [
            models.Index(fields=["email", "is_used"], name="idx_signup_email_used"),
            models.Index(fields=["expires_at"], name="idx_signup_email_expires"),
        ]

    def __str__(self):
        return f"[회원가입 이메일] {self.email} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired

    @classmethod
    def generate_token(cls):
        return secrets.token_urlsafe(48)
