"""공통 권한/접근 가드."""

from rest_framework.exceptions import PermissionDenied, ValidationError


class AccessGuard:
    @staticmethod
    def is_staff(user) -> bool:
        return bool(user and user.is_authenticated and user.is_staff)

    @staticmethod
    def is_superuser(user) -> bool:
        return bool(user and user.is_authenticated and user.is_superuser)

    @staticmethod
    def require_staff(user, message: str = "운영자 권한이 필요합니다.") -> None:
        if not AccessGuard.is_staff(user):
            raise PermissionDenied(message)

    @staticmethod
    def require_superuser(user, message: str = "최고 관리자 권한이 필요합니다.") -> None:
        if not AccessGuard.is_superuser(user):
            raise PermissionDenied(message)

    @staticmethod
    def require_other_user(
        actor_id: int,
        target_id: int,
        *,
        field_name: str = "user_id",
        message: str,
    ) -> None:
        if actor_id == target_id:
            raise ValidationError({field_name: [message]})

    @staticmethod
    def require_room_participant(user_id: int, room, message: str) -> None:
        if room.host_id != user_id and room.guest_id != user_id:
            raise PermissionDenied(message)
