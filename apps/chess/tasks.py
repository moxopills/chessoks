from django.utils import timezone

from celery import shared_task

from apps.chess.models import Game
from apps.chess.services import GameService


@shared_task
def handle_timeouts() -> int:
    """진행 중 게임의 타임아웃 처리"""
    now = timezone.now()
    games = Game.objects.filter(result="playing", turn_started_at__isnull=False).only(
        "id",
        "current_turn",
        "turn_started_at",
        "white_time_remaining",
        "black_time_remaining",
    )

    updated = 0
    for game in games:
        elapsed = (now - game.turn_started_at).total_seconds()
        if game.current_turn == "white":
            remaining = game.white_time_remaining - elapsed
        else:
            remaining = game.black_time_remaining - elapsed

        if remaining <= 0:
            GameService.apply_timeout(game, game.current_turn, now)
            updated += 1

    return updated
