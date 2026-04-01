from __future__ import annotations

from django.contrib.auth import get_user_model

User = get_user_model()


class UserQueryService:
    """유저 조회용 공통 서비스."""

    @staticmethod
    def top_players(limit: int = 10):
        return (
            User.objects.filter(is_active=True)
            .select_related("stats")
            .order_by("-stats__rating")[:limit]
        )

    @staticmethod
    def active_players():
        return User.objects.filter(is_active=True)
