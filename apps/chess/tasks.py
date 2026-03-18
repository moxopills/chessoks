import logging
from datetime import timedelta

from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError, models, transaction
from django.utils import timezone

from asgiref.sync import async_to_sync
from celery import shared_task
from channels.layers import get_channel_layer
from rest_framework.exceptions import ValidationError

from apps.chess.models import Game, LobbyMessage, Puzzle, Room
from apps.chess.services import AiService, GameService, PuzzleService

logger = logging.getLogger(__name__)
MATCH_ROOM_TYPES = ["quick", "random"]


def _build_game_end_payload(game: Game) -> dict:
    """게임 종료 브로드캐스트 페이로드 생성"""
    return {
        "type": "game_end",
        "game_id": game.id,
        "result": game.result,
        "fen": game.fen,
        "pgn": game.pgn,
        "current_turn": game.current_turn,
        "white_time_remaining": game.white_time_remaining,
        "black_time_remaining": game.black_time_remaining,
        "turn_started_at": game.turn_started_at.isoformat() if game.turn_started_at else None,
    }


def _broadcast_game_end(channel_layer, game: Game) -> None:
    """게임 종료 브로드캐스트 (플레이어 + 관전자)"""
    if not channel_layer:
        return
    payload = _build_game_end_payload(game)
    message = {"type": "broadcast", "payload": payload}
    try:
        async_to_sync(channel_layer.group_send)(f"chess_room_{game.room_id}", message)
        async_to_sync(channel_layer.group_send)(f"chess_room_{game.room_id}_spectators", message)
    except Exception as exc:
        logger.error("_broadcast_game_end failed game=%s: %s", game.id, exc)


@shared_task
def handle_timeouts() -> int:
    """진행 중 게임의 타임아웃 처리"""
    now = timezone.now()
    updated = 0
    channel_layer = get_channel_layer()

    with transaction.atomic():
        # skip_locked=True: 이미 락된 게임은 건너뜀 (다음 태스크에서 처리)
        games = (
            Game.objects.select_for_update(skip_locked=True)
            .filter(result="playing", turn_started_at__isnull=False)
            .select_related("room", "white_player", "black_player")
        )

        for game in games:
            elapsed = (now - game.turn_started_at).total_seconds()
            remaining = (
                game.white_time_remaining
                if game.current_turn == "white"
                else game.black_time_remaining
            ) - elapsed

            disconnected = False
            for color in ("white", "black"):
                key = GameService._cache_key("disconnect", game.id, color)
                ts = cache.get(key)
                if ts is None:
                    continue
                if now.timestamp() - ts >= GameService.DISCONNECT_GRACE_SECONDS:
                    try:
                        GameService.apply_disconnect_forfeit(game, color, now)
                        _broadcast_game_end(channel_layer, game)
                        updated += 1
                        disconnected = True
                        break
                    except ObjectDoesNotExist as exc:
                        logger.warning("Game %s not found during disconnect: %s", game.id, exc)
                    except DatabaseError as exc:
                        logger.error(
                            "Database error during disconnect for game %s: %s", game.id, exc
                        )

            if disconnected:
                continue

            if remaining <= 0:
                try:
                    GameService.apply_timeout(game, game.current_turn, now)
                    _broadcast_game_end(channel_layer, game)
                    updated += 1
                except ObjectDoesNotExist as exc:
                    logger.warning("Game %s not found during timeout: %s", game.id, exc)
                except DatabaseError as exc:
                    logger.error("Database error during timeout for game %s: %s", game.id, exc)

    return updated


@shared_task
def cleanup_stale_waiting_rooms(timeout_minutes: int = 3) -> int:
    """오래된 빠른 대전 대기방 정리"""
    cutoff = timezone.now() - timedelta(minutes=timeout_minutes)
    deleted, _ = Room.objects.filter(
        room_type__in=MATCH_ROOM_TYPES,
        status="waiting",
        guest__isnull=True,
        created_at__lt=cutoff,
    ).delete()
    return deleted


@shared_task
def cleanup_inactive_rooms(stale_minutes: int = 30) -> dict:
    """유휴/비정상 방 정리"""
    now = timezone.now()
    cutoff = now - timedelta(minutes=stale_minutes)

    stale_rooms = Room.objects.filter(
        status__in=["waiting", "ready"], updated_at__lt=cutoff
    ).filter(models.Q(guest__isnull=True) | models.Q(room_type__in=MATCH_ROOM_TYPES))
    stale_deleted, _ = stale_rooms.delete()

    # 빠른 대전 결과는 전적에 남겨야 하므로 finished quick room은 삭제하지 않음
    finished_quick_deleted = 0

    abnormal_rooms = (
        Room.objects.filter(status="playing", started_at__lt=cutoff)
        .exclude(games__result="playing")
        .distinct()
    )
    abnormal_updated = abnormal_rooms.update(status="finished", finished_at=now)

    return {
        "stale_deleted": stale_deleted,
        "finished_quick_deleted": finished_quick_deleted,
        "abnormal_updated": abnormal_updated,
    }


@shared_task
def cleanup_lobby_messages(retention_days: int = 3) -> int:
    """로비 채팅 메시지 보관 기간 정리"""
    cutoff = timezone.now() - timedelta(days=retention_days)
    deleted, _ = LobbyMessage.objects.filter(created_at__lt=cutoff).delete()
    return deleted


def _build_move_payload(result, game: Game) -> dict:
    payload = {
        "type": "move",
        "game_id": game.id,
        "fen": game.fen,
        "current_turn": game.current_turn,
        "result": game.result,
        "white_time_remaining": game.white_time_remaining,
        "black_time_remaining": game.black_time_remaining,
        "turn_started_at": game.turn_started_at.isoformat() if game.turn_started_at else None,
        "move": result.move.san if result and result.move else None,
    }
    if result and result.move:
        payload["pgn_append"] = {
            "san": result.move.san,
            "move_number": result.move.move_number,
            "player_color": result.move.player_color,
        }
        payload["last_move"] = {
            "from": result.move.from_square,
            "to": result.move.to_square,
            "uci": result.move.uci,
            "san": result.move.san,
            "is_check": result.move.is_check,
            "is_checkmate": result.move.is_checkmate,
            "is_capture": result.move.is_capture,
            "is_castling": result.move.is_castling,
            "is_en_passant": result.move.is_en_passant,
            "promotion": result.move.promotion,
        }
        if result.captured_letter and result.captured_color:
            payload["last_move"]["capture"] = {
                "piece": result.captured_letter,
                "color": result.captured_color,
            }
    if result and result.commentary:
        payload["commentary"] = result.commentary
        payload["commentary_level"] = result.commentary_level
        payload["commentary_color"] = result.commentary_color
    return payload


def _ai_move_lock_key(game_id: int, move_count: int) -> str:
    """AI 수 중복 방지용 캐시 키"""
    return f"ai_move_lock:{game_id}:{move_count}"


@shared_task
def handle_ai_move(game_id: int) -> bool:
    """AI 착수 처리 (idempotency 보장)"""
    import time

    try:
        game = Game.objects.select_related("room", "white_player", "black_player").get(pk=game_id)
    except Game.DoesNotExist:
        return False

    if game.result != "playing":
        return False

    room_type = game.room.room_type
    level = AiService.ROOM_TYPE_TO_LEVEL.get(room_type)
    if not level:
        return False

    ai_user = AiService.get_ai_user(level)
    ai_color = "white" if game.white_player_id == ai_user.id else "black"
    if game.current_turn != ai_color:
        return False

    # Idempotency: 동일 move_count에 대해 중복 실행 방지
    lock_key = _ai_move_lock_key(game_id, game.move_count)
    if not cache.add(lock_key, True, timeout=60):
        logger.info("AI move skipped (duplicate) game=%s move_count=%s", game_id, game.move_count)
        return False

    decision = AiService.choose_move(game.fen, level)
    if not decision:
        cache.delete(lock_key)
        return False

    delay_ms = AiService.get_delay_ms(level)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    start = time.monotonic()
    try:
        result = GameService.make_move(game.id, ai_user, decision.uci)
    except Exception as exc:
        cache.delete(lock_key)
        logger.error("AI move failed game=%s error=%s", game_id, exc)
        raise
    elapsed_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "AI move game=%s level=%s uci=%s score=%.2f elapsed_ms=%s",
        game.id,
        level,
        decision.uci,
        decision.score,
        elapsed_ms,
    )
    channel_layer = get_channel_layer()
    payload = _build_move_payload(result, result.game)
    message = {"type": "broadcast", "payload": payload}
    try:
        async_to_sync(channel_layer.group_send)(f"chess_room_{game.room_id}", message)
        async_to_sync(channel_layer.group_send)(f"chess_room_{game.room_id}_spectators", message)
    except Exception as exc:
        logger.error("AI move broadcast failed game=%s: %s", game_id, exc)
    return True


@shared_task
def select_daily_puzzle() -> str:
    """일일 퍼즐 자동 선정(자정 배치)"""
    selected = []
    errors = []
    for level in PuzzleService.ALL_LEVELS:
        try:
            daily = PuzzleService.select_daily_puzzle(level=level)
            selected.append(f"{daily.level}:{daily.puzzle_id}")
        except ValidationError as exc:
            msg = f"{level}:validation:{exc.detail}"
            logger.warning("select_daily_puzzle validation error: %s", msg)
            errors.append(msg)
        except Exception as exc:
            msg = f"{level}:error:{exc}"
            logger.exception("select_daily_puzzle failed: %s", msg)
            errors.append(msg)
    base = f"selected:{timezone.localdate()}:{','.join(selected)}"
    if errors:
        return f"{base}|errors:{' | '.join(errors)}"
    return base


@shared_task
def warmup_daily_puzzles() -> str:
    """주기적 퍼즐 보정(누락 레벨 자동 생성)"""
    selected = []
    errors = []
    for level in PuzzleService.ALL_LEVELS:
        try:
            daily = PuzzleService.get_or_create_daily_puzzle(level=level)
            selected.append(f"{daily.level}:{daily.puzzle_id}")
        except ValidationError as exc:
            msg = f"{level}:validation:{exc.detail}"
            logger.warning("warmup_daily_puzzles validation error: %s", msg)
            errors.append(msg)
        except Exception as exc:
            msg = f"{level}:error:{exc}"
            logger.exception("warmup_daily_puzzles failed: %s", msg)
            errors.append(msg)
    base = f"warmup:{timezone.localdate()}:{','.join(selected)}"
    if errors:
        return f"{base}|errors:{' | '.join(errors)}"
    return base


@shared_task
def monitor_puzzle_inventory() -> str:
    """퍼즐 재고 상태 점검(운영 로그용)"""
    total = Puzzle.objects.count()
    bands = {
        PuzzleService.LEVEL_EASY: Puzzle.objects.filter(rating__gte=800, rating__lte=1199).count(),
        PuzzleService.LEVEL_MEDIUM: Puzzle.objects.filter(
            rating__gte=1200, rating__lte=1799
        ).count(),
        PuzzleService.LEVEL_HARD: Puzzle.objects.filter(rating__gte=1800, rating__lte=2600).count(),
    }
    message = f"puzzle_inventory total={total} easy={bands['easy']} medium={bands['medium']} hard={bands['hard']}"
    if total <= 0 or any(count <= 0 for count in bands.values()):
        logger.warning(message)
    else:
        logger.info(message)
    return message
