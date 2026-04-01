from __future__ import annotations

from django.contrib.auth.hashers import check_password, make_password


class RoomSecurityService:
    """방 비밀번호 처리 서비스."""

    @staticmethod
    def hash_password(raw_password: str) -> str:
        return make_password(raw_password)

    @staticmethod
    def verify_password(hashed_password: str, raw_password: str) -> bool:
        return check_password(raw_password, hashed_password)
