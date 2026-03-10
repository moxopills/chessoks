from django.db import models
from django.db.models import Count, OuterRef, Subquery

from rest_framework.exceptions import NotFound, ValidationError

from apps.chess.models import Game, Room


class RoomQueryService:
    """방 조회 서비스"""

    VALID_ROOM_TYPES = {choice[0] for choice in Room.ROOM_TYPE_CHOICES}
    VALID_STATUSES = {choice[0] for choice in Room.STATUS_CHOICES}
    HIDDEN_ROOM_PREFIXES = ("ai_",)
    MATCH_HIDE_STATUSES = {"waiting", "ready"}

    @staticmethod
    def _base_queryset():
        """방 조회 공통 QuerySet (N+1 방지용 annotate 포함)."""
        playing_game_subquery = Subquery(
            Game.objects.filter(room_id=OuterRef("pk"), result="playing")
            .order_by("-created_at")
            .values("id")[:1]
        )
        return Room.objects.select_related("host__stats", "guest__stats").annotate(
            current_game_id_annotated=playing_game_subquery,
            spectator_count_annotated=Count("spectators", distinct=True),
        )

    @staticmethod
    def list_rooms(
        *,
        user,
        room_type: str | None,
        status: str | None,
        limit: int,
        offset: int,
        no_count: bool = False,
    ) -> tuple[int, list[Room]]:
        queryset = RoomQueryService._base_queryset().order_by("-created_at")

        if room_type:
            if room_type not in RoomQueryService.VALID_ROOM_TYPES:
                raise ValidationError({"room_type": "유효하지 않은 방 타입입니다."})
            queryset = queryset.filter(room_type=room_type)
        else:
            # 기본 목록에서는 매칭형 방(quick/random)의 대기/준비만 숨기고
            # 게임 중(playing)은 관전 가능하도록 노출한다.
            if status is None or status in RoomQueryService.MATCH_HIDE_STATUSES:
                queryset = queryset.exclude(
                    room_type__in=["quick", "random"],
                    status__in=RoomQueryService.MATCH_HIDE_STATUSES,
                )
            # AI 방은 기본 목록에서 제외
            for prefix in RoomQueryService.HIDDEN_ROOM_PREFIXES:
                queryset = queryset.exclude(room_type__startswith=prefix)

        if status:
            if status not in RoomQueryService.VALID_STATUSES:
                raise ValidationError({"status": "유효하지 않은 상태입니다."})
            queryset = queryset.filter(status=status)
        else:
            queryset = queryset.exclude(status="finished")

        rooms = list(queryset[offset : offset + limit])
        if no_count:
            return len(rooms), rooms
        total = queryset.count()
        return total, rooms

    @staticmethod
    def get_room(room_id: int, user) -> Room:
        try:
            room = RoomQueryService._base_queryset().get(pk=room_id)
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
            RoomQueryService._base_queryset()
            .filter(status__in=["waiting", "ready"])
            .filter(models.Q(host=user) | models.Q(guest=user))
            .order_by("-created_at")
            .first()
        )

    @staticmethod
    def get_active_room(user) -> Room | None:
        if not user or not getattr(user, "is_authenticated", False):
            return None
        return (
            RoomQueryService._base_queryset()
            .filter(status="playing")
            .filter(models.Q(host=user) | models.Q(guest=user))
            .order_by("-started_at", "-created_at")
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
