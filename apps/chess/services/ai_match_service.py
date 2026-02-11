from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from apps.chess.models import Game, Room
from apps.chess.services.ai_service import AiService
from apps.chess.utils import assign_colors, broadcast_room_state, broadcast_room_update


class AiMatchService:
    """AI 대전 매칭/생성 서비스"""

    logger = logging.getLogger(__name__)

    @staticmethod
    @transaction.atomic
    def create_ai_match(user, level: str) -> tuple[Room, Game]:
        level = level.lower()
        room_type = AiService.LEVEL_TO_ROOM_TYPE.get(level)
        if not room_type:
            raise ValueError("지원하지 않는 AI 난이도입니다.")

        ai_user = AiService.get_ai_user(level)
        room = Room.objects.create(
            host=user,
            guest=ai_user,
            room_type=room_type,
            status="playing",
            title=f"AI 대전 ({level})",
            allow_spectators=False,
            host_ready=True,
            guest_ready=True,
            host_start_confirmed=True,
            guest_start_confirmed=True,
            started_at=timezone.now(),
        )
        white_player, black_player = assign_colors(room.host, room.guest)
        game = Game.objects.create(room=room, white_player=white_player, black_player=black_player)
        broadcast_room_update(room)
        broadcast_room_state(room)
        AiMatchService.logger.info(
            "AI match created game=%s room=%s level=%s host=%s ai=%s",
            game.id,
            room.id,
            level,
            user.id,
            ai_user.id,
        )
        if game.white_player_id == ai_user.id:
            from apps.chess.tasks import handle_ai_move

            handle_ai_move.delay(game.id)
        return room, game
