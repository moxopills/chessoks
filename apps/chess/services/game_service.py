from __future__ import annotations

import logging
from dataclasses import dataclass

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

import chess
from apps.accounts.models import UserStats
from apps.accounts.services import RankingService
from apps.chess.engine import board as rule_engine
from apps.chess.models import Game, Move
from apps.chess.services.rating_service import RatingService
from apps.notifications.services import NotificationService


@dataclass(frozen=True)
class MoveResult:
    game: Game
    move: Move | None
    captured_letter: str | None = None
    captured_color: str | None = None
    commentary: str | None = None
    commentary_level: str | None = None
    commentary_color: str | None = None


class GameService:
    """체스 게임 진행 서비스 (서버 authoritative)"""

    logger = logging.getLogger(__name__)
    DRAW_OFFER_TTL = 300
    REMATCH_OFFER_TTL = 90
    DISCONNECT_GRACE_SECONDS = 180
    TIER_ORDER = {
        "Unranked": -1,
        "Beginner": 0,
        "Junior": 1,
        "Intermediate": 2,
        "Advanced": 3,
        "Expert": 4,
        "Master": 5,
    }

    @staticmethod
    @transaction.atomic
    def make_move(game_id: int, player, uci: str, promotion: str | None = None) -> MoveResult:
        game = GameService._get_game_for_update(game_id)

        if game.result != "playing":
            raise ValidationError("이미 종료된 게임입니다.")

        if game.room.status != "playing":
            raise ValidationError("게임이 아직 시작되지 않았습니다.")

        player_color = GameService._player_color(game, player)
        if player_color != game.current_turn:
            raise ValidationError("현재 차례가 아닙니다.")

        move_uci = GameService._normalize_uci(uci, promotion)
        if not move_uci:
            raise ValidationError("이동 정보가 올바르지 않습니다.")

        GameService._precheck_move(game.fen, move_uci)

        now = timezone.now()
        time_spent = GameService._calc_time_spent(game, now)
        remaining_after = GameService._remaining_after_spent(game, player_color, time_spent)
        if remaining_after <= 0:
            GameService.apply_timeout(game, player_color, now)
            return MoveResult(game=game, move=None)

        board = chess.Board(game.fen)
        pre_board = board.copy(stack=False)
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
        captured_letter = None
        captured_color = None
        if is_capture:
            capture_square = move.to_square
            if is_en_passant:
                offset = -8 if board.turn == chess.WHITE else 8
                capture_square = move.to_square + offset
            captured_piece = board.piece_at(capture_square)
            if captured_piece:
                captured_letter = captured_piece.symbol().upper()
                captured_color = "white" if captured_piece.color == chess.WHITE else "black"

        board.push(move)
        new_fen = board.fen()

        is_check = board.is_check()
        is_checkmate = board.is_checkmate()
        result = GameService._determine_result(board)
        if result == "playing" and not any(board.legal_moves):
            if board.is_check():
                result = "checkmate_black" if board.turn == chess.WHITE else "checkmate_white"
            else:
                result = "stalemate"

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
            captured_piece=captured_letter or "",  # 잡힌 기물 저장 (성능 최적화)
            captured_color=captured_color or "",  # 잡힌 기물 색상 저장
            promotion=GameService._promotion_symbol(move),
            fen_after_move=new_fen,
            time_spent=time_spent,
        )
        commentary, commentary_level = GameService._build_commentary(
            pre_board=pre_board,
            post_board=board,
            move=move,
            player_color=player_color,
            is_capture=is_capture,
            is_castling=is_castling,
            is_en_passant=is_en_passant,
            is_check=is_check,
            is_checkmate=is_checkmate,
            promotion=GameService._promotion_symbol(move),
        )

        GameService._apply_time_increment(game, player_color, remaining_after)
        game.fen = new_fen
        game.pgn = GameService._append_pgn(game.pgn, san, move_number, player_color)
        game.move_count += 1
        game.current_turn = "white" if board.turn == chess.WHITE else "black"
        game.turn_started_at = now

        started_at_set = False
        rating_info = None
        if result != "playing":
            game.result = result
            game.finished_at = now
            rating_info = GameService._apply_post_game_updates(game)
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
        if result != "playing":
            GameService._notify_game_end(game, rating_info)
        return MoveResult(
            game=game,
            move=move_obj,
            captured_letter=captured_letter,
            captured_color=captured_color,
            commentary=commentary,
            commentary_level=commentary_level,
            commentary_color=player_color,
        )

    @staticmethod
    @transaction.atomic
    def resign(game_id: int, player) -> Game:
        game = GameService._get_game_for_update(game_id)
        if game.result != "playing":
            raise ValidationError("이미 종료된 게임입니다.")

        player_color = GameService._player_color(game, player)
        game.result = "resignation_white" if player_color == "white" else "resignation_black"
        game.finished_at = timezone.now()
        rating_info = GameService._apply_post_game_updates(game)
        game.save(update_fields=["result", "finished_at"])
        GameService._notify_game_end(game, rating_info)
        GameService._clear_cache("draw_offer", game.id)
        GameService._clear_cache("disconnect", game.id)
        return game

    @staticmethod
    @transaction.atomic
    def request_draw(game_id: int, player) -> tuple[Game | None, str, str]:
        game = GameService._get_game_for_update(game_id)
        if game.result != "playing":
            raise ValidationError("이미 종료된 게임입니다.")

        player_color = GameService._player_color(game, player)
        opponent_color = "black" if player_color == "white" else "white"
        key = GameService._cache_key("draw_offer", game.id, player_color)
        opponent_key = GameService._cache_key("draw_offer", game.id, opponent_color)

        # cache.delete()는 삭제 성공 시 True 반환 (원자적 연산)
        if cache.delete(opponent_key):
            game.result = "draw_agreement"
            game.finished_at = timezone.now()
            rating_info = GameService._apply_post_game_updates(game)
            game.save(update_fields=["result", "finished_at"])
            GameService._notify_game_end(game, rating_info)
            return game, "accepted", player_color

        cache.set(key, True, timeout=GameService.DRAW_OFFER_TTL)
        return None, "pending", player_color

    @staticmethod
    @transaction.atomic
    def request_rematch(game_id: int, player) -> tuple[Game | None, str, str]:
        game = GameService._get_game_for_update(game_id)
        if game.result == "playing":
            raise ValidationError("진행 중인 게임에는 리매치를 요청할 수 없습니다.")
        if GameService._is_competitive_room(game.room.room_type):
            raise ValidationError("경쟁전에서는 리매치를 요청할 수 없습니다.")

        player_color = GameService._player_color(game, player)
        opponent_color = "black" if player_color == "white" else "white"
        key = GameService._cache_key("rematch_offer", game.id, player_color)
        opponent_key = GameService._cache_key("rematch_offer", game.id, opponent_color)

        # cache.delete()는 삭제 성공 시 True 반환 (원자적 연산)
        if cache.delete(opponent_key):
            rematch_game = GameService._create_rematch_game(game)
            GameService._notify_rematch(
                game,
                status="accepted",
                sender_color=player_color,
                rematch_game_id=rematch_game.id,
            )
            return rematch_game, "accepted", player_color

        cache.set(key, True, timeout=GameService.REMATCH_OFFER_TTL)
        GameService._notify_rematch(game, status="requested", sender_color=player_color)
        return None, "pending", player_color

    @staticmethod
    def decline_rematch(game_id: int, player) -> tuple[bool, str]:
        """리매치 요청 거절"""
        game = Game.objects.select_related("white_player", "black_player").get(pk=game_id)
        if game.result == "playing":
            raise ValidationError("진행 중인 게임입니다.")
        if GameService._is_competitive_room(game.room.room_type):
            raise ValidationError("경쟁전에서는 리매치를 사용할 수 없습니다.")

        player_color = GameService._player_color(game, player)
        opponent_color = "black" if player_color == "white" else "white"
        opponent_key = GameService._cache_key("rematch_offer", game.id, opponent_color)

        # 상대방의 리매치 요청이 있으면 삭제
        if cache.delete(opponent_key):
            GameService._notify_rematch(game, status="declined", sender_color=player_color)
            return True, player_color
        return False, player_color

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
    def _precheck_move(fen: str, move_uci: str) -> None:
        position = rule_engine.from_fen(fen)
        legal_moves = {
            rule_engine.move_to_uci(move) for move in rule_engine.generate_legal_moves(position)
        }
        if move_uci not in legal_moves:
            raise ValidationError("허용되지 않는 수입니다.")

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
    def _build_commentary(
        *,
        pre_board: chess.Board,
        post_board: chess.Board,
        move: chess.Move,
        player_color: str,
        is_capture: bool,
        is_castling: bool,
        is_en_passant: bool,
        is_check: bool,
        is_checkmate: bool,
        promotion: str,
    ) -> tuple[str | None, str | None]:
        if is_checkmate:
            return "체크메이트! 승리에 가까워졌습니다.", "major"
        if is_check:
            return "체크! 상대 왕을 압박했습니다.", "positive"
        if promotion:
            return "프로모션! 강력한 기물로 승격했습니다.", "positive"
        if is_castling:
            return "킹을 안전하게 보호했습니다.", "positive"
        if is_capture or is_en_passant:
            return "기물을 잡아 유리함을 만들었습니다.", "positive"

        # 간단한 중앙 장악 힌트
        center_squares = {chess.D4, chess.E4, chess.D5, chess.E5}
        if move.to_square in center_squares:
            return "중앙을 장악했습니다. 좋은 전개입니다.", "positive"

        # 기물 노출 경고 (단순 휴리스틱)
        moved_color = chess.WHITE if player_color == "white" else chess.BLACK
        opponent = not moved_color
        if post_board.is_attacked_by(opponent, move.to_square) and not post_board.is_attacked_by(
            moved_color, move.to_square
        ):
            return "기물이 노출될 수 있습니다. 다음 수를 주의하세요.", "warning"

        return None, None

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
        rating_info = GameService._apply_post_game_updates(game)
        game.finished_at = now
        game.save(
            update_fields=[
                "result",
                "finished_at",
                "white_time_remaining",
                "black_time_remaining",
            ]
        )
        GameService._notify_game_end(game, rating_info)
        GameService._clear_cache("draw_offer", game.id)
        GameService._clear_cache("rematch_offer", game.id)
        GameService._clear_cache("disconnect", game.id)

    @staticmethod
    def check_and_apply_timeout(game_id: int) -> Game | None:
        """시간 초과 체크 및 적용"""
        game = Game.objects.select_for_update().get(id=game_id)
        if game.result != "playing" or not game.time_limit:
            return game

        now = timezone.now()
        time_spent = GameService._calc_time_spent(game, now)
        current_turn = game.current_turn
        remaining = GameService._remaining_after_spent(game, current_turn, time_spent)

        if remaining <= 0:
            GameService.apply_timeout(game, current_turn, now)
        return game

    @staticmethod
    def apply_disconnect_forfeit(game: Game, player_color: str, now) -> None:
        if player_color == "white":
            game.result = "resignation_white"
        else:
            game.result = "resignation_black"
        rating_info = GameService._apply_post_game_updates(game)
        game.finished_at = now
        game.save(update_fields=["result", "finished_at"])
        GameService._notify_game_end(game, rating_info)
        GameService._clear_cache("draw_offer", game.id)
        GameService._clear_cache("rematch_offer", game.id)
        GameService._clear_cache("disconnect", game.id)

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

    @staticmethod
    def _is_competitive_room(room_type: str) -> bool:
        return room_type == "quick"

    @staticmethod
    def _apply_post_game_updates(game: Game) -> dict | None:
        if game.room.room_type.startswith("ai_"):
            return None
        if GameService._is_competitive_room(game.room.room_type):
            return GameService._apply_rating_update(game)
        GameService._apply_stats_only(game)
        return None

    @staticmethod
    def _apply_stats_only(game: Game) -> None:
        # 게스트는 통계 업데이트 제외
        if game.white_player.is_guest or game.black_player.is_guest:
            return
        white_stats, _ = UserStats.objects.get_or_create(user=game.white_player)
        black_stats, _ = UserStats.objects.get_or_create(user=game.black_player)
        RatingService.update_stats_only(white_stats, black_stats, game.result)
        white_stats.save()
        black_stats.save()
        RankingService.invalidate_leaderboard_cache()

    @staticmethod
    def _apply_rating_update(game: Game) -> dict | None:
        # 게스트는 레이팅/통계 업데이트 제외
        if game.white_player.is_guest or game.black_player.is_guest:
            return None
        white_stats, _ = UserStats.objects.get_or_create(user=game.white_player)
        black_stats, _ = UserStats.objects.get_or_create(user=game.black_player)

        white_before = white_stats.rating
        black_before = black_stats.rating
        white_tier_before = white_stats.rank_tier
        black_tier_before = black_stats.rank_tier

        RatingService.update_ratings_and_stats(white_stats, black_stats, game.result)
        white_stats.save()
        black_stats.save()
        RankingService.invalidate_leaderboard_cache()
        return {
            "white": {
                "before": white_before,
                "after": white_stats.rating,
                "tier_before": white_tier_before,
                "tier_after": white_stats.rank_tier,
            },
            "black": {
                "before": black_before,
                "after": black_stats.rating,
                "tier_before": black_tier_before,
                "tier_after": black_stats.rank_tier,
            },
        }

    @staticmethod
    def _get_game_for_update(game_id: int) -> Game:
        return (
            Game.objects.select_for_update()
            .select_related("room", "white_player", "black_player")
            .get(pk=game_id)
        )

    @staticmethod
    def _cache_key(prefix: str, game_id: int, player_color: str) -> str:
        """통합 캐시 키 생성 (draw_offer, disconnect, rematch_offer)"""
        return f"chess:{prefix}:{game_id}:{player_color}"

    @staticmethod
    def _clear_cache(prefix: str, game_id: int) -> None:
        """양측 캐시 키 삭제"""
        cache.delete(GameService._cache_key(prefix, game_id, "white"))
        cache.delete(GameService._cache_key(prefix, game_id, "black"))

    @staticmethod
    def _create_rematch_game(game: Game) -> Game:
        """기존 Room에서 흑백을 바꿔 새 Game 생성"""
        room = game.room
        # 흑백 교체
        white_player = game.black_player
        black_player = game.white_player

        # Room의 host/guest 업데이트
        room.host = white_player
        room.guest = black_player
        room.status = "playing"
        room.started_at = timezone.now()
        room.finished_at = None
        room.host_ready = True
        room.guest_ready = True
        room.host_start_confirmed = True
        room.guest_start_confirmed = True
        room.save(
            update_fields=[
                "host",
                "guest",
                "status",
                "started_at",
                "finished_at",
                "host_ready",
                "guest_ready",
                "host_start_confirmed",
                "guest_start_confirmed",
            ]
        )

        from apps.chess.utils import broadcast_room_state, broadcast_room_update

        broadcast_room_update(room)
        broadcast_room_state(room)

        return Game.objects.create(room=room, white_player=white_player, black_player=black_player)

    @staticmethod
    def _notify_game_end(game: Game, rating_info: dict | None) -> None:
        reason = GameService._result_reason(game.result)
        from django.core.cache import cache

        ai_room = game.room.room_type.startswith("ai_")
        competitive_room = GameService._is_competitive_room(game.room.room_type)

        for color, player in (("white", game.white_player), ("black", game.black_player)):
            cache.delete(f"user_profile_{player.id}")
            outcome = GameService._result_outcome(game.result, color)
            outcome_text = {"win": "승리", "loss": "패배", "draw": "무승부"}[outcome]
            if reason:
                message = f"{reason}로 {outcome_text}했습니다."
            else:
                message = f"{outcome_text}했습니다."
            NotificationService.create_notification(
                user=player,
                type="game_result",
                title="게임 종료",
                message=message,
                payload={"game_id": game.id, "result": game.result, "outcome": outcome},
            )

            if rating_info:
                rating_before = rating_info[color]["before"]
                rating_after = rating_info[color]["after"]
                delta = rating_after - rating_before
                NotificationService.create_notification(
                    user=player,
                    type="rating_change",
                    title="레이팅 변동",
                    message=f"{rating_before} -> {rating_after} ({delta:+d})",
                    payload={
                        "game_id": game.id,
                        "before": rating_before,
                        "after": rating_after,
                        "delta": delta,
                    },
                )

                tier_before = rating_info[color]["tier_before"]
                tier_after = rating_info[color]["tier_after"]
                if GameService._tier_rank(tier_after) > GameService._tier_rank(tier_before):
                    NotificationService.create_notification(
                        user=player,
                        type="tier_promotion",
                        title="티어 승격",
                        message=f"{tier_after} 티어로 승격했습니다.",
                        payload={"before": tier_before, "after": tier_after, "game_id": game.id},
                    )

            if competitive_room:
                stats = (
                    UserStats.objects.filter(user=player).only("competitive_games_played").first()
                )
                if stats and stats.competitive_games_played < 5:
                    NotificationService.create_notification(
                        user=player,
                        type="placement_progress",
                        title="배치전 진행",
                        message=f"배치 진행: {stats.competitive_games_played}/5",
                        payload={"game_id": game.id, "played": stats.competitive_games_played},
                    )

        if ai_room:
            GameService.logger.info(
                "AI game end game=%s result=%s white=%s black=%s",
                game.id,
                game.result,
                game.white_player_id,
                game.black_player_id,
            )

        from apps.chess.utils import broadcast_room_update

        room = game.room
        room.status = "finished"
        room.finished_at = game.finished_at or timezone.now()
        room.save(update_fields=["status", "finished_at"])
        broadcast_room_update(room)

    @staticmethod
    def _notify_rematch(
        game: Game, *, status: str, sender_color: str, rematch_game_id: int | None = None
    ) -> None:
        sender = game.white_player if sender_color == "white" else game.black_player
        opponent = game.black_player if sender_color == "white" else game.white_player
        if status == "requested":
            NotificationService.create_notification(
                user=opponent,
                type="rematch",
                title="리매치 요청",
                message=f"{sender.nickname}님이 리매치를 요청했습니다.",
                payload={"game_id": game.id, "room_id": game.room_id, "from": sender_color},
            )
            return
        if status == "accepted":
            NotificationService.create_notification(
                user=sender,
                type="rematch",
                title="리매치 성사",
                message="리매치가 성사되었습니다.",
                payload={
                    "game_id": game.id,
                    "room_id": game.room_id,
                    "status": status,
                    "rematch_game_id": rematch_game_id,
                },
            )
            NotificationService.create_notification(
                user=opponent,
                type="rematch",
                title="리매치 성사",
                message="리매치가 성사되었습니다.",
                payload={
                    "game_id": game.id,
                    "room_id": game.room_id,
                    "status": status,
                    "rematch_game_id": rematch_game_id,
                },
            )
            return
        if status == "declined":
            NotificationService.create_notification(
                user=opponent,
                type="rematch",
                title="리매치 거절",
                message=f"{sender.nickname}님이 리매치를 거절했습니다.",
                payload={"game_id": game.id, "room_id": game.room_id, "from": sender_color},
            )

    @staticmethod
    def _tier_rank(tier: str) -> int:
        return GameService.TIER_ORDER.get(tier, 0)

    @staticmethod
    def _result_outcome(result: str, player_color: str) -> str:
        white_win = {
            "white_win",
            "checkmate_white",
            "timeout_black",
            "resignation_black",
        }
        black_win = {
            "black_win",
            "checkmate_black",
            "timeout_white",
            "resignation_white",
        }
        if result in white_win:
            return "win" if player_color == "white" else "loss"
        if result in black_win:
            return "loss" if player_color == "white" else "win"
        return "draw"

    @staticmethod
    def _result_reason(result: str) -> str:
        reasons = {
            "checkmate_white": "체크메이트",
            "checkmate_black": "체크메이트",
            "timeout_white": "시간 초과",
            "timeout_black": "시간 초과",
            "resignation_white": "기권",
            "resignation_black": "기권",
            "stalemate": "스테일메이트",
            "draw_insufficient": "기물 부족",
            "draw_repetition": "삼중 반복",
            "draw_fifty_move": "50수 규칙",
            "draw_agreement": "합의 무승부",
        }
        return reasons.get(result, "")
