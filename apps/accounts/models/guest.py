"""비회원 게스트 세션 모델"""

import secrets
from datetime import timedelta

from django.db import models
from django.utils import timezone


class GuestSession(models.Model):
    """비회원 게스트 세션"""

    token = models.CharField(max_length=64, unique=True, db_index=True)
    nickname = models.CharField(max_length=20)
    display_name = models.CharField(max_length=30)  # "[게스트] 닉네임" 형태
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    last_activity = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["expires_at"]),
            models.Index(fields=["token"]),
        ]

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=24)
        if not self.display_name:
            self.display_name = f"[게스트] {self.nickname}"
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @classmethod
    def cleanup_expired(cls):
        """만료된 세션 삭제"""
        deleted, _ = cls.objects.filter(expires_at__lt=timezone.now()).delete()
        return deleted

    def __str__(self):
        return f"{self.display_name} ({self.token[:8]}...)"
