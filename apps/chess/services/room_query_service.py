from rest_framework.exceptions import NotFound, ValidationError

from apps.chess.models import Room


class RoomQueryService:
    """방 조회 서비스"""

    VALID_ROOM_TYPES = {choice[0] for choice in Room.ROOM_TYPE_CHOICES}
    VALID_STATUSES = {choice[0] for choice in Room.STATUS_CHOICES}

    @staticmethod
    def list_rooms(
        *, room_type: str | None, status: str | None, limit: int, offset: int
    ) -> tuple[int, list[Room]]:
        queryset = (
            Room.objects.filter(is_private=False)
            .select_related("host__stats", "guest__stats")
            .order_by("-created_at")
        )

        if room_type:
            if room_type not in RoomQueryService.VALID_ROOM_TYPES:
                raise ValidationError({"room_type": "유효하지 않은 방 타입입니다."})
            queryset = queryset.filter(room_type=room_type)

        if status:
            if status not in RoomQueryService.VALID_STATUSES:
                raise ValidationError({"status": "유효하지 않은 상태입니다."})
            queryset = queryset.filter(status=status)
        else:
            queryset = queryset.exclude(status="finished")

        total = queryset.count()
        return total, list(queryset[offset : offset + limit])

    @staticmethod
    def get_room(room_id: int, user) -> Room:
        try:
            room = Room.objects.select_related("host__stats", "guest__stats").get(pk=room_id)
        except Room.DoesNotExist:
            raise NotFound("방을 찾을 수 없습니다.") from None

        if room.is_private and not RoomQueryService._has_access(room, user):
            raise NotFound("방에 접근할 수 없습니다.")
        return room

    @staticmethod
    def _has_access(room: Room, user) -> bool:
        return room.host_id == user.id or room.guest_id == user.id
