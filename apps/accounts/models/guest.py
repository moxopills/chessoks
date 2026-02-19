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
        """만료된 세션 삭제 (연결된 게스트 User도 함께 삭제)"""
        from apps.accounts.models import User

        expired_sessions = cls.objects.filter(expires_at__lt=timezone.now())
        # 연결된 게스트 User ID 수집
        guest_user_ids = list(
            expired_sessions.exclude(user__isnull=True).values_list("user_id", flat=True)
        )
        # 세션 삭제
        deleted, _ = expired_sessions.delete()
        # 게스트 User 삭제
        if guest_user_ids:
            User.objects.filter(id__in=guest_user_ids, is_guest=True).delete()
        return deleted

    def get_or_create_user(self):
        """게임 참여용 임시 User 생성 또는 반환"""
        if self.user:
            return self.user

        from apps.accounts.models import User

        # 고유한 이메일 생성 (게스트용)
        guest_email = f"guest_{self.token[:16]}@guest.local"

        user = User.objects.create(
            email=guest_email,
            nickname=self.display_name,
            is_guest=True,
            is_active=True,
            email_verified=False,
        )
        user.set_unusable_password()
        user.save()

        # UserStats 생성
        from apps.accounts.models import UserStats

        UserStats.objects.create(user=user)

        self.user = user
        self.save(update_fields=["user"])

        return user

    def __str__(self):
        return f"{self.display_name} ({self.token[:8]}...)"
