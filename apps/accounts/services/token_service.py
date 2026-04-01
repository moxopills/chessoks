from __future__ import annotations

import secrets

from django.db.models import Q
from django.utils import timezone

from apps.accounts.models import AuthToken, SignupEmailToken


class TokenService:
    """인증 토큰 관련 계산/생성/정리 로직 서비스."""

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    def is_expired(token) -> bool:
        return timezone.now() > token.expires_at

    @classmethod
    def is_valid(cls, token) -> bool:
        return not token.is_used and not cls.is_expired(token)

    @staticmethod
    def delete_expired_auth_tokens(token_type: str | None = None) -> int:
        now = timezone.now()
        queryset = AuthToken.objects.filter(Q(expires_at__lt=now) | Q(is_used=True))
        if token_type:
            queryset = queryset.filter(token_type=token_type)
        deleted_count, _ = queryset.delete()
        return deleted_count

    @staticmethod
    def delete_expired_signup_tokens() -> int:
        now = timezone.now()
        queryset = SignupEmailToken.objects.filter(Q(expires_at__lt=now) | Q(is_used=True))
        deleted_count, _ = queryset.delete()
        return deleted_count

    @staticmethod
    def invalidate_existing_signup_tokens(email: str) -> None:
        SignupEmailToken.objects.filter(email=email, is_used=False).update(
            is_used=True,
            used_at=timezone.now(),
        )
