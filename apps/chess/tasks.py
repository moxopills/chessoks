import logging
from datetime import timedelta

from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError, models, transaction
from django.utils import timezone

from celery import shared_task

from apps.chess.models import Game, LobbyMessage, Room
from apps.chess.services import GameService

logger = logging.getLogger(__name__)


@shared_task
def handle_timeouts() -> int:
    """진행 중 게임의 타임아웃 처리"""
    now = timezone.now()
    updated = 0

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

            if remaining <= 0:
                try:
                    GameService.apply_timeout(game, game.current_turn, now)
                    updated += 1
                except ObjectDoesNotExist as exc:
                    logger.warning("Game %s not found during timeout: %s", game.id, exc)
                except DatabaseError as exc:
                    logger.error("Database error during timeout for game %s: %s", game.id, exc)

    return updated


@shared_task
def cleanup_stale_waiting_rooms(timeout_minutes: int = 5) -> int:
    """오래된 빠른 대전 대기방 정리"""
    cutoff = timezone.now() - timedelta(minutes=timeout_minutes)
    deleted, _ = Room.objects.filter(
        room_type="quick", status="waiting", guest__isnull=True, created_at__lt=cutoff
    ).delete()
    return deleted


@shared_task
def cleanup_inactive_rooms(stale_minutes: int = 30) -> dict:
    """유휴/비정상 방 정리"""
    now = timezone.now()
    cutoff = now - timedelta(minutes=stale_minutes)

    stale_rooms = Room.objects.filter(
        status__in=["waiting", "ready"], updated_at__lt=cutoff
    ).filter(models.Q(guest__isnull=True) | models.Q(room_type="quick"))
    stale_deleted, _ = stale_rooms.delete()

    abnormal_rooms = (
        Room.objects.filter(status="playing", started_at__lt=cutoff)
        .exclude(games__result="playing")
        .distinct()
    )
    abnormal_updated = abnormal_rooms.update(status="finished", finished_at=now)

    return {"stale_deleted": stale_deleted, "abnormal_updated": abnormal_updated}


@shared_task
def cleanup_lobby_messages(retention_days: int = 3) -> int:
    """로비 채팅 메시지 보관 기간 정리"""
    cutoff = timezone.now() - timedelta(days=retention_days)
    deleted, _ = LobbyMessage.objects.filter(created_at__lt=cutoff).delete()
    return deleted
