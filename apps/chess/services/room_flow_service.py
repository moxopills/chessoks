import random

from django.db import transaction
from django.utils import timezone

from rest_framework.exceptions import NotFound, ValidationError

from apps.chess.models import Game, Room


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
                white_player, black_player = RoomFlowService._assign_colors(room.host, room.guest)
                game = Game.objects.create(
                    room=room, white_player=white_player, black_player=black_player
                )

        room.save(
            update_fields=["host_start_confirmed", "guest_start_confirmed", "status", "started_at"]
        )
        return room, game

    @staticmethod
    def _ensure_player(room: Room, user) -> None:
        if user != room.host and user != room.guest:
            raise ValidationError("방 참가자가 아닙니다.")

    @staticmethod
    def _compute_status(room: Room) -> str:
        if room.guest_id is None:
            return "waiting"
        if room.host_ready and room.guest_ready:
            return "ready"
        if room.status == "finished":
            return "finished"
        return "waiting"

    @staticmethod
    def _assign_colors(host, guest):
        if random.choice([True, False]):
            return host, guest
        return guest, host
