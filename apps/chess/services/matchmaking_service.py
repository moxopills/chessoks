import random

from django.db import transaction
from django.db.models import F, Value
from django.db.models.functions import Abs
from django.utils import timezone

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from apps.accounts.models import UserStats
from apps.chess.models import Game, Room


class MatchmakingService:
    """빠른 대전 매칭 서비스"""

    MAX_RATING_DIFF = 125

    @staticmethod
    @transaction.atomic
    def quick_match(user) -> tuple[Room, Game | None, str]:
        stats, _ = UserStats.objects.get_or_create(user=user)
        rating = stats.rating
        room = MatchmakingService._find_best_room(user, rating)

        if room is None:
            room = Room.objects.create(
                room_type="quick",
                title="",
                host=user,
                status="waiting",
                is_private=False,
            )
            return room, None, "waiting"

        room.guest = user
        room.status = "playing"
        room.started_at = timezone.now()
        room.save(update_fields=["guest", "status", "started_at"])

        white_player, black_player = MatchmakingService._assign_colors(room.host, room.guest)
        game = Game.objects.create(room=room, white_player=white_player, black_player=black_player)

        MatchmakingService._notify_match(room, game)
        return room, game, "matched"

    @staticmethod
    def _find_best_room(user, rating):
        return (
            Room.objects.select_for_update(skip_locked=True)
            .filter(
                room_type="quick",
                status="waiting",
                is_private=False,
                guest__isnull=True,
                host__stats__rating__gte=rating - MatchmakingService.MAX_RATING_DIFF,
                host__stats__rating__lte=rating + MatchmakingService.MAX_RATING_DIFF,
            )
            .exclude(host=user)
            .select_related("host__stats")
            .annotate(abs_diff=Abs(F("host__stats__rating") - Value(rating)))
            .order_by("abs_diff", "created_at")
            .first()
        )

    @staticmethod
    def _assign_colors(host, guest):
        if random.choice([True, False]):
            return host, guest
        return guest, host

    @staticmethod
    def cancel_match(user) -> bool:
        """대기 중인 빠른 대전 취소"""
        deleted, _ = Room.objects.filter(
            room_type="quick", host=user, status="waiting", guest__isnull=True
        ).delete()
        return deleted > 0

    @staticmethod
    def _notify_match(room: Room, game: Game) -> None:
        """매칭 완료 시 WebSocket 알림"""
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return

        payload = {
            "type": "broadcast",
            "payload": {
                "type": "match_found",
                "room_id": room.id,
                "game_id": game.id,
                "white_player": game.white_player.nickname,
                "black_player": game.black_player.nickname,
                "fen": game.fen,
                "white_time_remaining": game.white_time_remaining,
                "black_time_remaining": game.black_time_remaining,
            },
        }
        async_to_sync(channel_layer.group_send)(f"chess_room_{room.id}", payload)
