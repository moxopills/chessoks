from __future__ import annotations

import re

from django.core.exceptions import ValidationError
from django.utils import timezone

SQUARE_PATTERN = re.compile(r"^[a-h][1-8]$")


class ChessModelIntegrityService:
    """chess 모델 무결성/초기화 서비스."""

    @staticmethod
    def validate_room(room) -> None:
        if room.is_private and not room.password:
            raise ValidationError("비공개방은 비밀번호가 필요합니다")
        if room.time_limit < 0:
            raise ValidationError("시간 제한은 음수일 수 없습니다")
        if room.host == room.guest:
            raise ValidationError("호스트와 게스트가 동일할 수 없습니다")

    @staticmethod
    def validate_game(game) -> None:
        if game.white_player == game.black_player:
            raise ValidationError("백과 흑 플레이어가 동일할 수 없습니다")
        if game.move_count < 0:
            raise ValidationError("수 카운트는 음수가 될 수 없습니다")

    @staticmethod
    def apply_initial_game_state(game) -> None:
        if game.pk:
            return
        time_limit_seconds = game.room.time_limit * 60
        game.white_time_remaining = time_limit_seconds
        game.black_time_remaining = time_limit_seconds
        if not game.turn_started_at:
            game.turn_started_at = timezone.now()

    @staticmethod
    def validate_move(move) -> None:
        if not SQUARE_PATTERN.match(move.from_square):
            raise ValidationError(f"잘못된 출발 좌표: {move.from_square}")
        if not SQUARE_PATTERN.match(move.to_square):
            raise ValidationError(f"잘못된 도착 좌표: {move.to_square}")
        if move.is_check and move.is_checkmate:
            raise ValidationError("체크와 체크메이트는 동시에 참일 수 없습니다")
        if move.move_number <= 0:
            raise ValidationError("착수 번호는 1 이상이어야 합니다")
