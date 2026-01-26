from django.db import transaction
from django.utils import timezone

from rest_framework.exceptions import NotFound, ValidationError

from apps.chess.models import Game, Room
from apps.chess.utils import assign_colors, broadcast_room_removed, broadcast_room_update


class RoomFlowService:
    """방 준비/시작 플로우 서비스"""

    @staticmethod
    @transaction.atomic
    def set_ready(room_id: int, user, ready: bool) -> Room:
        try:
            room = Room.objects.select_for_update().get(pk=room_id)
        except Room.DoesNotExist:
            raise NotFound("방을 찾을 수 없습니다.") from None
        RoomFlowService._ensure_player(room, user)

        if room.status == "playing":
            raise ValidationError("게임 진행 중에는 준비 상태를 변경할 수 없습니다.")

        if user == room.host:
            room.host_ready = ready
        else:
            room.guest_ready = ready

        if not ready:
            room.host_start_confirmed = False
            room.guest_start_confirmed = False

        room.status = RoomFlowService._compute_status(room)
        room.save(
            update_fields=[
                "host_ready",
                "guest_ready",
                "host_start_confirmed",
                "guest_start_confirmed",
                "status",
            ]
        )
        broadcast_room_update(room)
        return room

    @staticmethod
    @transaction.atomic
    def confirm_start(room_id: int, user) -> tuple[Room, Game]:
        try:
            room = Room.objects.select_for_update().get(pk=room_id)
        except Room.DoesNotExist:
            raise NotFound("방을 찾을 수 없습니다.") from None
        RoomFlowService._ensure_player(room, user)

        if room.status == "playing":
            raise ValidationError("이미 게임이 시작되었습니다.")

        if room.guest_id is None:
            raise ValidationError("게스트가 입장해야 시작할 수 있습니다.")
        if not (room.host_ready and room.guest_ready):
            raise ValidationError("두 명 모두 준비가 필요합니다.")

        if user == room.host:
            room.host_start_confirmed = True
        else:
            room.guest_start_confirmed = True

        game = None
        if room.host_start_confirmed and room.guest_start_confirmed:
            room.status = "playing"
            room.started_at = timezone.now()
            game = room.games.filter(result="playing").first()
            if game is None:
                white_player, black_player = assign_colors(room.host, room.guest)
                game = Game.objects.create(
                    room=room, white_player=white_player, black_player=black_player
                )

        room.save(
            update_fields=["host_start_confirmed", "guest_start_confirmed", "status", "started_at"]
        )
        broadcast_room_update(room)
        return room, game

    @staticmethod
    @transaction.atomic
    def join_room(room_id: int, user, password: str | None = None) -> Room:
        try:
            room = Room.objects.select_for_update().get(pk=room_id)
        except Room.DoesNotExist:
            raise NotFound("방을 찾을 수 없습니다.") from None

        if room.status in {"playing", "finished"}:
            raise ValidationError("입장할 수 없는 방입니다.")

        if room.host_id == user.id or room.guest_id == user.id:
            return room

        if room.guest_id is not None:
            raise ValidationError("이미 인원이 가득 찼습니다.")

        if room.is_private:
            if not password or not room.check_password(password):
                raise ValidationError({"password": ["비밀번호가 올바르지 않습니다."]})

        room.guest = user
        room.host_start_confirmed = False
        room.guest_start_confirmed = False
        room.status = RoomFlowService._compute_status(room)
        room.save(
            update_fields=[
                "guest",
                "host_start_confirmed",
                "guest_start_confirmed",
                "status",
            ]
        )
        broadcast_room_update(room)
        return room

    @staticmethod
    @transaction.atomic
    def leave_room(room_id: int, user) -> tuple[bool, Room | None]:
        try:
            room = Room.objects.select_for_update().get(pk=room_id)
        except Room.DoesNotExist:
            raise NotFound("방을 찾을 수 없습니다.") from None
        RoomFlowService._ensure_player(room, user)

        if room.status == "playing":
            raise ValidationError("게임 진행 중에는 나갈 수 없습니다.")

        if user == room.host:
            room_id_value = room.id
            room.delete()
            broadcast_room_removed(room_id_value)
            return True, None

        room.guest = None
        room.host_ready = False
        room.guest_ready = False
        room.host_start_confirmed = False
        room.guest_start_confirmed = False
        room.started_at = None
        room.status = "waiting"
        room.save(
            update_fields=[
                "guest",
                "host_ready",
                "guest_ready",
                "host_start_confirmed",
                "guest_start_confirmed",
                "started_at",
                "status",
            ]
        )
        broadcast_room_update(room)
        return False, room

    @staticmethod
    def _ensure_player(room: Room, user) -> None:
        if user != room.host and user != room.guest:
            raise ValidationError("방 참가자가 아닙니다.")

    @staticmethod
    def _compute_status(room: Room) -> str:
        if room.host_ready and room.guest_ready:
            return "ready"
        if room.status == "finished":
            return "finished"
        if room.guest_id is None:
            return "waiting"
        return "waiting"
