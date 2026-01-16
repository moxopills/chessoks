from __future__ import annotations

from dataclasses import dataclass

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

import chess
from apps.chess.models import Game, Move


@dataclass(frozen=True)
class MoveResult:
    game: Game
    move: Move | None


class GameService:
    """체스 게임 진행 서비스 (서버 authoritative)"""

    @staticmethod
    @transaction.atomic
    def make_move(game_id: int, player, uci: str, promotion: str | None = None) -> MoveResult:
        game = (
            Game.objects.select_for_update()
            .select_related("room", "white_player", "black_player")
            .get(pk=game_id)
        )

        if game.result != "playing":
            raise ValidationError("이미 종료된 게임입니다.")

        player_color = GameService._player_color(game, player)
        if player_color != game.current_turn:
            raise ValidationError("현재 차례가 아닙니다.")

        move_uci = GameService._normalize_uci(uci, promotion)
        if not move_uci:
            raise ValidationError("이동 정보가 올바르지 않습니다.")

        now = timezone.now()
        time_spent = GameService._calc_time_spent(game, now)
        remaining_after = GameService._remaining_after_spent(game, player_color, time_spent)
        if remaining_after <= 0:
            GameService.apply_timeout(game, player_color, now)
            return MoveResult(game=game, move=None)

        board = chess.Board(game.fen)
        GameService._ensure_turn_matches(board, player_color)

        move = chess.Move.from_uci(move_uci)
        if move not in board.legal_moves:
            raise ValidationError("허용되지 않는 수입니다.")

        piece = board.piece_at(move.from_square)
        if piece is None:
            raise ValidationError("출발 위치에 기물이 없습니다.")

        san = board.san(move)
        is_capture = board.is_capture(move)
        is_castling = board.is_castling(move)
        is_en_passant = board.is_en_passant(move)

        board.push(move)
        new_fen = board.fen()

        is_check = board.is_check()
        is_checkmate = board.is_checkmate()
        result = GameService._determine_result(board)

        move_number = (game.move_count // 2) + 1
        move_obj = Move.objects.create(
            game=game,
            move_number=move_number,
            player_color=player_color,
            piece=piece.symbol().upper(),
            from_square=chess.square_name(move.from_square),
            to_square=chess.square_name(move.to_square),
            san=san,
            uci=move_uci,
            is_capture=is_capture,
            is_check=is_check,
            is_checkmate=is_checkmate,
            is_castling=is_castling,
            is_en_passant=is_en_passant,
            promotion=GameService._promotion_symbol(move),
            fen_after_move=new_fen,
            time_spent=time_spent,
        )

        GameService._apply_time_increment(game, player_color, remaining_after)
        game.fen = new_fen
        game.pgn = GameService._append_pgn(game.pgn, san, move_number, player_color)
        game.move_count += 1
        game.current_turn = "white" if board.turn == chess.WHITE else "black"
        game.turn_started_at = now

        started_at_set = False
        if result != "playing":
            game.result = result
            game.finished_at = now
        elif game.started_at is None:
            game.started_at = now
            started_at_set = True

        update_fields = [
            "fen",
            "pgn",
            "move_count",
            "current_turn",
            "turn_started_at",
            "white_time_remaining",
            "black_time_remaining",
        ]
        if result != "playing":
            update_fields += ["result", "finished_at"]
        elif started_at_set:
            update_fields += ["started_at"]

        game.save(update_fields=update_fields)
        return MoveResult(game=game, move=move_obj)

    @staticmethod
    def _player_color(game: Game, player) -> str:
        if player == game.white_player:
            return "white"
        if player == game.black_player:
            return "black"
        raise ValidationError("게임 참가자가 아닙니다.")

    @staticmethod
    def _ensure_turn_matches(board: chess.Board, player_color: str) -> None:
        expected = chess.WHITE if player_color == "white" else chess.BLACK
        if board.turn != expected:
            raise ValidationError("현재 보드 턴과 요청이 일치하지 않습니다.")

    @staticmethod
    def _normalize_uci(uci: str | None, promotion: str | None) -> str:
        if not uci:
            return ""
        base = uci.strip().lower()
        if len(base) not in (4, 5):
            return ""
        if promotion and len(base) == 4:
            return f"{base}{promotion.lower()}"
        return base

    @staticmethod
    def _promotion_symbol(move: chess.Move) -> str:
        if move.promotion is None:
            return ""
        return chess.piece_symbol(move.promotion).upper()

    @staticmethod
    def _calc_time_spent(game: Game, now) -> float:
        turn_started_at = game.turn_started_at or game.updated_at or game.created_at
        return max(0.0, (now - turn_started_at).total_seconds())

    @staticmethod
    def _remaining_after_spent(game: Game, player_color: str, time_spent: float) -> int:
        if player_color == "white":
            return int(game.white_time_remaining - time_spent)
        return int(game.black_time_remaining - time_spent)

    @staticmethod
    def _apply_time_increment(game: Game, player_color: str, remaining_after: int) -> None:
        increment = game.room.increment_seconds
        if player_color == "white":
            game.white_time_remaining = remaining_after + increment
        else:
            game.black_time_remaining = remaining_after + increment

    @staticmethod
    def apply_timeout(game: Game, player_color: str, now) -> None:
        if player_color == "white":
            game.result = "timeout_white"
            game.white_time_remaining = 0
        else:
            game.result = "timeout_black"
            game.black_time_remaining = 0
        game.finished_at = now
        game.save(
            update_fields=[
                "result",
                "finished_at",
                "white_time_remaining",
                "black_time_remaining",
            ]
        )

    @staticmethod
    def _determine_result(board: chess.Board) -> str:
        if board.is_checkmate():
            return "checkmate_black" if board.turn == chess.WHITE else "checkmate_white"
        if board.is_stalemate():
            return "stalemate"
        if board.is_insufficient_material():
            return "draw_insufficient"
        if board.can_claim_threefold_repetition():
            return "draw_repetition"
        if board.can_claim_fifty_moves():
            return "draw_fifty_move"
        return "playing"

    @staticmethod
    def _append_pgn(pgn: str, san: str, move_number: int, player_color: str) -> str:
        prefix = f"{move_number}. {san}" if player_color == "white" else san
        if not pgn:
            return prefix
        return f"{pgn} {prefix}"
