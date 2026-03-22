from django.db import transaction
from django.utils import timezone

from rest_framework.exceptions import NotFound, ValidationError

from apps.chess.models import Game, Room
from apps.chess.utils import (
    assign_colors,
    broadcast_room_removed,
    broadcast_room_state,
    broadcast_room_update,
)


class RoomFlowService:
    """방 준비/시작 플로우 서비스"""

    AUTO_START_ROOM_TYPES = {"quick", "random"}

    @staticmethod
    def _schedule_room_broadcast(room: Room) -> None:
        transaction.on_commit(lambda: broadcast_room_update(room))
        transaction.on_commit(lambda: broadcast_room_state(room))

    @staticmethod
    def _schedule_room_removed(room_id: int) -> None:
        transaction.on_commit(lambda: broadcast_room_removed(room_id))

    @staticmethod
    def _ensure_available(user) -> None:
        if user.is_suspended:
            raise ValidationError("정지된 계정입니다.")

    @staticmethod
    def _get_room_for_update(room_id: int) -> Room:
        try:
            return Room.objects.select_for_update().get(pk=room_id)
        except Room.DoesNotExist:
            raise NotFound("방을 찾을 수 없습니다.") from None

    @staticmethod
    def _clear_start_confirmations(room: Room) -> None:
        room.host_start_confirmed = False
        room.guest_start_confirmed = False

    @staticmethod
    def _create_game_if_missing(room: Room) -> Game:
        game = room.games.filter(result="playing").first()
        if game is not None:
            return game
        white_player, black_player = assign_colors(room.host, room.guest)
        return Game.objects.create(room=room, white_player=white_player, black_player=black_player)

    @staticmethod
    @transaction.atomic
    def set_ready(room_id: int, user, ready: bool) -> Room:
        RoomFlowService._ensure_available(user)
        room = RoomFlowService._get_room_for_update(room_id)
        RoomFlowService._ensure_player(room, user)

        if room.status == "playing":
            raise ValidationError("게임 진행 중에는 준비 상태를 변경할 수 없습니다.")

        if user == room.host:
            room.host_ready = ready
        else:
            room.guest_ready = ready

        if not ready:
            RoomFlowService._clear_start_confirmations(room)

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
        RoomFlowService._schedule_room_broadcast(room)
        return room

    @staticmethod
    @transaction.atomic
    def confirm_start(room_id: int, user) -> tuple[Room, Game]:
        RoomFlowService._ensure_available(user)
        room = RoomFlowService._get_room_for_update(room_id)
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
            game = RoomFlowService._create_game_if_missing(room)

        room.save(
            update_fields=["host_start_confirmed", "guest_start_confirmed", "status", "started_at"]
        )
        RoomFlowService._schedule_room_broadcast(room)
        return room, game

    @staticmethod
    @transaction.atomic
    def join_room(room_id: int, user, password: str | None = None) -> Room:
        RoomFlowService._ensure_available(user)
        room = RoomFlowService._get_room_for_update(room_id)

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
        RoomFlowService._clear_start_confirmations(room)
        if room.room_type in RoomFlowService.AUTO_START_ROOM_TYPES:
            room.status = "playing"
            room.started_at = timezone.now()
            RoomFlowService._create_game_if_missing(room)
        else:
            room.status = RoomFlowService._compute_status(room)
        room.save(
            update_fields=[
                "guest",
                "host_start_confirmed",
                "guest_start_confirmed",
                "status",
                "started_at",
            ]
        )
        RoomFlowService._schedule_room_broadcast(room)
        if room.host_id and room.host_id != user.id:
            from apps.notifications.services import NotificationService

            transaction.on_commit(
                lambda: NotificationService.create_notification(
                    user=room.host,
                    type="room_joined",
                    title="게스트 입장",
                    message=f"{user.nickname}님이 방에 입장했습니다.",
                    payload={"room_id": room.id},
                )
            )
        return room

    @staticmethod
    @transaction.atomic
    def leave_room(room_id: int, user) -> tuple[bool, Room | None]:
        room = RoomFlowService._get_room_for_update(room_id)
        RoomFlowService._ensure_player(room, user)

        if room.status == "playing":
            raise ValidationError("게임 진행 중에는 나갈 수 없습니다.")

        if user == room.host:
            room_id_value = room.id
            room.delete()
            RoomFlowService._schedule_room_removed(room_id_value)
            return True, None

        room.guest = None
        room.host_ready = False
        room.guest_ready = False
        RoomFlowService._clear_start_confirmations(room)
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
        RoomFlowService._schedule_room_broadcast(room)
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
