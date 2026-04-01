from __future__ import annotations

from django.utils import timezone


class UserStateService:
    """사용자 제재/상태 판정 전용 서비스."""

    @staticmethod
    def is_suspended(user) -> bool:
        if user is None:
            return False
        suspended_until = getattr(user, "suspended_until", None)
        return bool(suspended_until and timezone.now() < suspended_until)

    @staticmethod
    def is_muted(user) -> bool:
        if user is None:
            return False
        muted_until = getattr(user, "muted_until", None)
        return bool(muted_until and timezone.now() < muted_until)
