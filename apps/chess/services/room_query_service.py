from django.db.models import OuterRef, Subquery
from rest_framework.exceptions import NotFound, ValidationError

from apps.chess.models import Game, Room


class RoomQueryService:
    """방 조회 서비스"""

    VALID_ROOM_TYPES = {choice[0] for choice in Room.ROOM_TYPE_CHOICES}
    VALID_STATUSES = {choice[0] for choice in Room.STATUS_CHOICES}

    @staticmethod
    def list_rooms(
        *, user, room_type: str | None, status: str | None, limit: int, offset: int
    ) -> tuple[int, list[Room]]:
        playing_game_subquery = Subquery(
            Game.objects.filter(room_id=OuterRef("pk"), result="playing")
            .order_by("-created_at")
            .values("id")[:1]
        )
        queryset = (
            Room.objects.select_related("host__stats", "guest__stats")
            .annotate(current_game_id_annotated=playing_game_subquery)
            .order_by("-created_at")
        )

        if room_type:
            if room_type not in RoomQueryService.VALID_ROOM_TYPES:
                raise ValidationError({"room_type": "유효하지 않은 방 타입입니다."})
            queryset = queryset.filter(room_type=room_type)
        else:
            # 기본 목록에서는 빠른 대전의 대기/준비 방을 숨기되,
            # 게임 중 상태에서는 관전 가능하도록 제외하지 않는다.
            if status in (None, "waiting", "ready"):
                queryset = queryset.exclude(room_type="quick", status__in=["waiting", "ready"])

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
    def get_waiting_room(user) -> Room | None:
        if not user or not getattr(user, "is_authenticated", False):
            return None
        return (
            Room.objects.select_related("host__stats", "guest__stats")
            .filter(host=user, status__in=["waiting", "ready"], guest__isnull=True)
            .first()
        )

    @staticmethod
    def _has_access(room: Room, user) -> bool:
        return room.host_id == user.id or room.guest_id == user.id

    @staticmethod
    def create_room(
        user,
        *,
        room_type: str = "custom",
        title: str = "",
        time_limit: int = 15,
        increment_seconds: int = 10,
        password: str = "",
        allow_spectators: bool = True,
    ) -> Room:
        """방 생성"""
        if user.is_suspended:
            raise ValidationError("정지된 계정입니다.")
        room = Room(
            host=user,
            room_type=room_type,
            title=title or "",
            time_limit=time_limit,
            increment_seconds=increment_seconds,
            is_private=bool(password),
            allow_spectators=allow_spectators,
        )

        if password:
            room.set_password(password)

        room.save()
        from apps.chess.utils import broadcast_room_update

        broadcast_room_update(room)
        return room
