from __future__ import annotations

import secrets
from datetime import timedelta

from django.utils import timezone

from apps.accounts.models import GuestSession, User, UserStats


class GuestSessionService:
    """게스트 세션 관련 비즈니스 로직 서비스."""

    @staticmethod
    def is_expired(guest: GuestSession | None) -> bool:
        if guest is None:
            return True
        return timezone.now() > guest.expires_at

    @staticmethod
    def create_session(*, nickname: str, ip_address: str | None = None) -> GuestSession:
        return GuestSession.objects.create(
            token=secrets.token_urlsafe(32),
            nickname=nickname,
            display_name=f"[게스트] {nickname}",
            expires_at=timezone.now() + timedelta(hours=24),
            ip_address=ip_address,
        )

    @staticmethod
    def get_or_create_user(guest: GuestSession):
        if guest.user:
            return guest.user

        guest_email = f"guest_{guest.token[:16]}@guest.local"
        user = User.objects.create(
            email=guest_email,
            nickname=guest.display_name,
            is_guest=True,
            is_active=True,
            email_verified=False,
        )
        user.set_unusable_password()
        user.save(update_fields=["password"])
        UserStats.objects.create(user=user)

        guest.user = user
        guest.save(update_fields=["user"])
        return user

    @staticmethod
    def cleanup_expired() -> int:
        expired_sessions = GuestSession.objects.filter(expires_at__lt=timezone.now())
        guest_user_ids = list(
            expired_sessions.exclude(user__isnull=True).values_list("user_id", flat=True)
        )
        deleted, _ = expired_sessions.delete()
        if guest_user_ids:
            User.objects.filter(id__in=guest_user_ids, is_guest=True).delete()
        return deleted
