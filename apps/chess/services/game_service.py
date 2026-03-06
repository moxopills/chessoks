from __future__ import annotations

import logging
from dataclasses import dataclass

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

import chess
from apps.accounts.models import UserStats
from apps.accounts.models.skin import SkinPointLog
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

        if game.result != Game.Status.PLAYING:
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

        # 시간 초과 체크 (0.5초 Grace Period 적용)
        if remaining_after <= -0.5:
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
                captured_color = (
                    Game.Color.WHITE if captured_piece.color == chess.WHITE else Game.Color.BLACK
                )

        board.push(move)
        new_fen = board.fen()

        is_check = board.is_check()
        is_checkmate = board.is_checkmate()
        result = GameService._determine_result(board)
        if result == Game.Status.PLAYING and not any(board.legal_moves):
            if board.is_check():
                result = (
                    Game.Status.CHECKMATE_BLACK
                    if board.turn == chess.WHITE
                    else Game.Status.CHECKMATE_WHITE
                )
            else:
                result = Game.Status.STALEMATE

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
            captured_piece=captured_letter or "",
            captured_color=captured_color or "",
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
        game.current_turn = Game.Color.WHITE if board.turn == chess.WHITE else Game.Color.BLACK
        game.turn_started_at = now

        started_at_set = False
        rating_info = None
        if result != Game.Status.PLAYING:
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
        if result != Game.Status.PLAYING:
            update_fields += ["result", "finished_at"]
        elif started_at_set:
            update_fields += ["started_at"]

        game.save(update_fields=update_fields)

        if result != Game.Status.PLAYING:
            transaction.on_commit(lambda: GameService._notify_game_end(game, rating_info))

        # AI 턴 처리
        from apps.chess.services import AiService
        from apps.chess.tasks import handle_ai_move

        if (
            game.room.room_type in AiService.ROOM_TYPE_TO_LEVEL
            and game.result == Game.Status.PLAYING
        ):
            transaction.on_commit(lambda: handle_ai_move.delay(game.id))

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
        if game.result != Game.Status.PLAYING:
            raise ValidationError("이미 종료된 게임입니다.")

        player_color = GameService._player_color(game, player)
        game.result = (
            Game.Status.RESIGNATION_WHITE
            if player_color == Game.Color.WHITE
            else Game.Status.RESIGNATION_BLACK
        )
        game.finished_at = timezone.now()
        rating_info = GameService._apply_post_game_updates(game)
        game.save(update_fields=["result", "finished_at"])
        transaction.on_commit(lambda: GameService._notify_game_end(game, rating_info))
        GameService._clear_cache("draw_offer", game.id)
        GameService._clear_cache("disconnect", game.id)
        return game

    @staticmethod
    @transaction.atomic
    def request_draw(game_id: int, player) -> tuple[Game | None, str, str]:
        game = GameService._get_game_for_update(game_id)
        if game.result != Game.Status.PLAYING:
            raise ValidationError("이미 종료된 게임입니다.")

        player_color = GameService._player_color(game, player)
        opponent_color = Game.Color.BLACK if player_color == Game.Color.WHITE else Game.Color.WHITE
        key = GameService._cache_key("draw_offer", game.id, player_color)
        opponent_key = GameService._cache_key("draw_offer", game.id, opponent_color)

        # cache.delete()는 삭제 성공 시 True 반환 (원자적 연산)
        if cache.delete(opponent_key):
            game.result = Game.Status.DRAW_AGREEMENT
            game.finished_at = timezone.now()
            rating_info = GameService._apply_post_game_updates(game)
            game.save(update_fields=["result", "finished_at"])
            transaction.on_commit(lambda: GameService._notify_game_end(game, rating_info))
            return game, "accepted", player_color

        cache.set(key, True, timeout=GameService.DRAW_OFFER_TTL)
        return None, "pending", player_color

    @staticmethod
    @transaction.atomic
    def request_rematch(game_id: int, player) -> tuple[Game | None, str, str]:
        game = GameService._get_game_for_update(game_id)
        if game.result == Game.Status.PLAYING:
            raise ValidationError("진행 중인 게임에는 리매치를 요청할 수 없습니다.")
        if GameService._is_competitive_room(game.room.room_type):
            raise ValidationError("경쟁전에서는 리매치를 요청할 수 없습니다.")

        player_color = GameService._player_color(game, player)
        opponent_color = Game.Color.BLACK if player_color == Game.Color.WHITE else Game.Color.WHITE
        key = GameService._cache_key("rematch_offer", game.id, player_color)
        opponent_key = GameService._cache_key("rematch_offer", game.id, opponent_color)

        # cache.delete()는 삭제 성공 시 True 반환 (원자적 연산)
        if cache.delete(opponent_key):
            rematch_game = GameService._create_rematch_game(game)
            transaction.on_commit(
                lambda: GameService._notify_rematch(
                    game,
                    status="accepted",
                    sender_color=player_color,
                    rematch_game_id=rematch_game.id,
                )
            )
            return rematch_game, "accepted", player_color

        cache.set(key, True, timeout=GameService.REMATCH_OFFER_TTL)
        transaction.on_commit(
            lambda: GameService._notify_rematch(game, status="requested", sender_color=player_color)
        )
        return None, "pending", player_color

    @staticmethod
    def decline_rematch(game_id: int, player) -> tuple[bool, str]:
        """리매치 요청 거절"""
        game = Game.objects.select_related("white_player", "black_player").get(pk=game_id)
        if game.result == Game.Status.PLAYING:
            raise ValidationError("진행 중인 게임입니다.")
        if GameService._is_competitive_room(game.room.room_type):
            raise ValidationError("경쟁전에서는 리매치를 사용할 수 없습니다.")

        player_color = GameService._player_color(game, player)
        opponent_color = Game.Color.BLACK if player_color == Game.Color.WHITE else Game.Color.WHITE
        opponent_key = GameService._cache_key("rematch_offer", game.id, opponent_color)

        # 상대방의 리매치 요청이 있으면 삭제
        if cache.delete(opponent_key):
            transaction.on_commit(
                lambda: GameService._notify_rematch(
                    game, status="declined", sender_color=player_color
                )
            )
            return True, player_color
        return False, player_color

    @staticmethod
    def _player_color(game: Game, player) -> str:
        if player == game.white_player:
            return Game.Color.WHITE
        if player == game.black_player:
            return Game.Color.BLACK
        raise ValidationError("게임 참가자가 아닙니다.")

    @staticmethod
    def _ensure_turn_matches(board: chess.Board, player_color: str) -> None:
        expected = chess.WHITE if player_color == Game.Color.WHITE else chess.BLACK
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
        moved_color = chess.WHITE if player_color == Game.Color.WHITE else chess.BLACK
        opponent = not moved_color
        if post_board.is_attacked_by(opponent, move.to_square) and not post_board.is_attacked_by(
            moved_color, move.to_square
        ):
            return "기물이 노출될 수 있습니다. 다음 수를 주의하세요.", "warning"

        return None, None

    @staticmethod
    def _remaining_after_spent(game: Game, player_color: str, time_spent: float) -> int:
        if player_color == Game.Color.WHITE:
            return int(game.white_time_remaining - time_spent)
        return int(game.black_time_remaining - time_spent)

    @staticmethod
    def _apply_time_increment(game: Game, player_color: str, remaining_after: int) -> None:
        increment = game.room.increment_seconds
        if player_color == Game.Color.WHITE:
            game.white_time_remaining = remaining_after + increment
        else:
            game.black_time_remaining = remaining_after + increment

    @staticmethod
    def apply_timeout(game: Game, player_color: str, now) -> None:
        if player_color == Game.Color.WHITE:
            game.result = Game.Status.TIMEOUT_WHITE
            game.white_time_remaining = 0
        else:
            game.result = Game.Status.TIMEOUT_BLACK
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
        transaction.on_commit(lambda: GameService._notify_game_end(game, rating_info))
        GameService._clear_cache("draw_offer", game.id)
        GameService._clear_cache("rematch_offer", game.id)
        GameService._clear_cache("disconnect", game.id)

    @staticmethod
    def check_and_apply_timeout(game_id: int) -> Game | None:
        """시간 초과 체크 및 적용"""
        game = Game.objects.select_for_update().get(id=game_id)
        if game.result != Game.Status.PLAYING or not game.time_limit:
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
        if player_color == Game.Color.WHITE:
            game.result = Game.Status.RESIGNATION_WHITE
        else:
            game.result = Game.Status.RESIGNATION_BLACK
        rating_info = GameService._apply_post_game_updates(game)
        game.finished_at = now
        game.save(update_fields=["result", "finished_at"])
        transaction.on_commit(lambda: GameService._notify_game_end(game, rating_info))
        GameService._clear_cache("draw_offer", game.id)
        GameService._clear_cache("rematch_offer", game.id)
        GameService._clear_cache("disconnect", game.id)

    @staticmethod
    def _determine_result(board: chess.Board) -> str:
        if board.is_checkmate():
            return (
                Game.Status.CHECKMATE_BLACK
                if board.turn == chess.WHITE
                else Game.Status.CHECKMATE_WHITE
            )
        if board.is_stalemate():
            return Game.Status.STALEMATE
        if board.is_insufficient_material():
            return Game.Status.DRAW_INSUFFICIENT
        if board.can_claim_threefold_repetition():
            return Game.Status.DRAW_REPETITION
        if board.can_claim_fifty_moves():
            return Game.Status.DRAW_FIFTY_MOVE
        return Game.Status.PLAYING

    @staticmethod
    def _append_pgn(pgn: str, san: str, move_number: int, player_color: str) -> str:
        prefix = f"{move_number}. {san}" if player_color == Game.Color.WHITE else san
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
        white_delta, black_delta = GameService._apply_style_points(
            white_stats, black_stats, game.result
        )
        white_stats.save()
        black_stats.save()
        GameService._record_style_point_log(
            game.id, white_stats, white_delta, black_stats, black_delta
        )
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
        white_delta, black_delta = GameService._apply_style_points(
            white_stats, black_stats, game.result
        )
        white_stats.save()
        black_stats.save()
        GameService._record_style_point_log(
            game.id, white_stats, white_delta, black_stats, black_delta
        )
        try:
            from apps.accounts.services import SeasonService

            SeasonService.update_after_competitive_game(
                white_user_id=game.white_player_id,
                black_user_id=game.black_player_id,
                game_result=game.result,
            )
        except Exception as exc:
            GameService.logger.exception("Season update failed for game %s: %s", game.id, exc)
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
        cache.delete(GameService._cache_key(prefix, game_id, Game.Color.WHITE))
        cache.delete(GameService._cache_key(prefix, game_id, Game.Color.BLACK))

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

        # Room 관련 브로드캐스트는 Transaction 내에서 실행되어야 Room 변경 사항이 보임
        # 하지만 Redis 메시지 전송은 DB 락을 잡을 필요가 없으므로 on_commit 사용 권장.
        # 그러나 여기서는 Room 저장이 완료되었으므로 호출해도 무방.
        # 더 완벽하게 하려면:
        transaction.on_commit(lambda: broadcast_room_update(room))
        transaction.on_commit(lambda: broadcast_room_state(room))

        return Game.objects.create(room=room, white_player=white_player, black_player=black_player)

    @staticmethod
    def _notify_game_end(game: Game, rating_info: dict | None) -> None:
        reason = GameService._result_reason(game.result)
        from django.core.cache import cache

        ai_room = game.room.room_type.startswith("ai_")
        competitive_room = GameService._is_competitive_room(game.room.room_type)

        for color, player in (
            (Game.Color.WHITE, game.white_player),
            (Game.Color.BLACK, game.black_player),
        ):
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
        # 여기서도 on_commit을 쓰면 좋지만, _notify_game_end 자체가 이미 on_commit으로 호출되므로 중복 래핑됨.
        # 하지만 _notify_game_end가 동기적으로 호출될 수도 있으므로 안전장치로 놔둠.
        # 주의: 람다 내부에서 호출되므로 트랜잭션이 이미 끝난 상태일 수 있음.
        # 따라서 _notify_game_end는 트랜잭션 밖에서 실행되므로 on_commit을 또 쓸 필요는 없음.
        # 하지만 일관성을 위해 둠 (어차피 즉시 실행됨).
        broadcast_room_update(room)

    @staticmethod
    def _notify_rematch(
        game: Game, *, status: str, sender_color: str, rematch_game_id: int | None = None
    ) -> None:
        sender = game.white_player if sender_color == Game.Color.WHITE else game.black_player
        opponent = game.black_player if sender_color == Game.Color.WHITE else game.white_player
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
    def _apply_style_points(
        white_stats: UserStats, black_stats: UserStats, result: str
    ) -> tuple[int, int]:
        # 기본 지급: 완료한 경기당 10점
        white_delta = 10
        black_delta = 10
        white_stats.style_points = (white_stats.style_points or 0) + 10
        black_stats.style_points = (black_stats.style_points or 0) + 10

        white_win = {
            Game.Status.WHITE_WIN,
            Game.Status.CHECKMATE_WHITE,
            Game.Status.TIMEOUT_BLACK,
            Game.Status.RESIGNATION_BLACK,
        }
        black_win = {
            Game.Status.BLACK_WIN,
            Game.Status.CHECKMATE_BLACK,
            Game.Status.TIMEOUT_WHITE,
            Game.Status.RESIGNATION_WHITE,
        }
        draw_set = {
            Game.Status.DRAW,
            Game.Status.STALEMATE,
            Game.Status.DRAW_AGREEMENT,
            Game.Status.DRAW_REPETITION,
            Game.Status.DRAW_FIFTY_MOVE,
            Game.Status.DRAW_INSUFFICIENT,
        }

        if result in white_win:
            white_stats.style_points += 5
            white_delta += 5
        elif result in black_win:
            black_stats.style_points += 5
            black_delta += 5
        elif result in draw_set:
            white_stats.style_points += 2
            black_stats.style_points += 2
            white_delta += 2
            black_delta += 2
        return white_delta, black_delta

    @staticmethod
    def _record_style_point_log(
        game_id: int,
        white_stats: UserStats,
        white_delta: int,
        black_stats: UserStats,
        black_delta: int,
    ) -> None:
        white_reason = SkinPointLog.Reason.GAME_DRAW
        black_reason = SkinPointLog.Reason.GAME_DRAW
        if white_delta > black_delta:
            white_reason = SkinPointLog.Reason.GAME_WIN
            black_reason = SkinPointLog.Reason.GAME_LOSS
        elif black_delta > white_delta:
            white_reason = SkinPointLog.Reason.GAME_LOSS
            black_reason = SkinPointLog.Reason.GAME_WIN

        now = timezone.now()
        SkinPointLog.objects.bulk_create(
            [
                SkinPointLog(
                    user_id=white_stats.user_id,
                    amount=white_delta,
                    balance=white_stats.style_points,
                    reason=white_reason,
                    reference_id=str(game_id),
                    created_at=now,
                ),
                SkinPointLog(
                    user_id=black_stats.user_id,
                    amount=black_delta,
                    balance=black_stats.style_points,
                    reason=black_reason,
                    reference_id=str(game_id),
                    created_at=now,
                ),
            ]
        )

    @staticmethod
    def _tier_rank(tier: str) -> int:
        return GameService.TIER_ORDER.get(tier, 0)

    @staticmethod
    def _result_outcome(result: str, player_color: str) -> str:
        white_win = {
            Game.Status.WHITE_WIN,
            Game.Status.CHECKMATE_WHITE,
            Game.Status.TIMEOUT_BLACK,
            Game.Status.RESIGNATION_BLACK,
        }
        black_win = {
            Game.Status.BLACK_WIN,
            Game.Status.CHECKMATE_BLACK,
            Game.Status.TIMEOUT_WHITE,
            Game.Status.RESIGNATION_WHITE,
        }
        if result in white_win:
            return "win" if player_color == Game.Color.WHITE else "loss"
        if result in black_win:
            return "loss" if player_color == Game.Color.WHITE else "win"
        return "draw"

    @staticmethod
    def _result_reason(result: str) -> str:
        reasons = {
            Game.Status.CHECKMATE_WHITE: "체크메이트",
            Game.Status.CHECKMATE_BLACK: "체크메이트",
            Game.Status.TIMEOUT_WHITE: "시간 초과",
            Game.Status.TIMEOUT_BLACK: "시간 초과",
            Game.Status.RESIGNATION_WHITE: "기권",
            Game.Status.RESIGNATION_BLACK: "기권",
            Game.Status.STALEMATE: "스테일메이트",
            Game.Status.DRAW_INSUFFICIENT: "기물 부족",
            Game.Status.DRAW_REPETITION: "삼중 반복",
            Game.Status.DRAW_FIFTY_MOVE: "50수 규칙",
            Game.Status.DRAW_AGREEMENT: "합의 무승부",
        }
        return reasons.get(result, "")
