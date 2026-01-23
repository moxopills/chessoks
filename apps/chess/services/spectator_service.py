from rest_framework.exceptions import NotFound, ValidationError

from apps.chess.models import Room


class SpectatorService:
    """관전자 관리 서비스"""

    @staticmethod
    def list_spectators(room_id: int, user):
        room = SpectatorService._get_room(room_id)
        SpectatorService._ensure_access(room, user)
        return room, list(room.spectators.all())

    @staticmethod
    def add_spectator(room_id: int, user):
        room = SpectatorService._get_room(room_id)
        if not room.allow_spectators:
            raise ValidationError("관전을 허용하지 않는 방입니다.")
        if user == room.host or user == room.guest:
            raise ValidationError("플레이어는 관전자로 참가할 수 없습니다.")

        room.spectators.add(user)
        return room

    @staticmethod
    def remove_spectator(room_id: int, user):
        room = SpectatorService._get_room(room_id)
        room.spectators.remove(user)
        return room

    @staticmethod
    def _get_room(room_id: int) -> Room:
        try:
            return Room.objects.select_related("host", "guest").get(pk=room_id)
        except Room.DoesNotExist:
            raise NotFound("방을 찾을 수 없습니다.") from None

    @staticmethod
    def _ensure_access(room: Room, user) -> None:
        if room.is_private and user != room.host and user != room.guest:
            raise NotFound("방에 접근할 수 없습니다.")
        if not room.allow_spectators and user != room.host and user != room.guest:
            raise ValidationError("관전을 허용하지 않는 방입니다.")
