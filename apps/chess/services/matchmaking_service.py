from django.db import transaction
from django.utils import timezone

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from apps.accounts.models import UserStats
from apps.chess.models import Game, Room
from apps.chess.utils import assign_colors, broadcast_room_removed, broadcast_room_update
from apps.notifications.services import NotificationService


class MatchmakingService:
    """빠른 대전 매칭 서비스"""

    RATING_DIFF_TIERS = (
        (0, 125),
        (15, 175),
        (30, 250),
        (45, 350),
        (60, 500),
        (90, 650),
        (120, 800),
        (180, 1000),
        (300, 1200),
    )
    MAX_RATING_DIFF = RATING_DIFF_TIERS[-1][1]

    @staticmethod
    @transaction.atomic
    def quick_match(user) -> tuple[Room, Game | None, str]:
        existing = (
            Room.objects.select_for_update(skip_locked=True)
            .filter(room_type="quick", host=user, status="waiting", guest__isnull=True)
            .first()
        )
        if existing is not None:
            return existing, None, "waiting"

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
            broadcast_room_update(room)
            return room, None, "waiting"

        room.guest = user
        room.status = "playing"
        room.started_at = timezone.now()
        room.save(update_fields=["guest", "status", "started_at"])
        broadcast_room_update(room)

        white_player, black_player = assign_colors(room.host, room.guest)
        game = Game.objects.create(room=room, white_player=white_player, black_player=black_player)

        MatchmakingService._notify_match(room, game)
        return room, game, "matched"

    @staticmethod
    def _find_best_room(user, rating):
        now = timezone.now()
        rooms = list(
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
        )

        best_room = None
        best_diff = None
        for room in rooms:
            host_rating = room.host.stats.rating
            diff = abs(host_rating - rating)
            wait_seconds = (now - room.created_at).total_seconds()
            allowed = MatchmakingService._allowed_rating_diff(wait_seconds)
            if diff > allowed:
                continue
            if (
                best_room is None
                or diff < best_diff
                or (diff == best_diff and room.created_at < best_room.created_at)
            ):
                best_room = room
                best_diff = diff

        return best_room

    @staticmethod
    def _allowed_rating_diff(wait_seconds: float) -> int:
        allowed = MatchmakingService.RATING_DIFF_TIERS[0][1]
        for threshold, diff in MatchmakingService.RATING_DIFF_TIERS:
            if wait_seconds >= threshold:
                allowed = diff
        return allowed

    @staticmethod
    def cancel_match(user) -> bool:
        """대기 중인 빠른 대전 취소"""
        room = (
            Room.objects.filter(room_type="quick", host=user, status="waiting", guest__isnull=True)
            .only("id")
            .first()
        )
        if room is None:
            return False
        room_id = room.id
        room.delete()
        broadcast_room_removed(room_id)
        return True

    @staticmethod
    def _notify_match(room: Room, game: Game) -> None:
        """매칭 완료 시 WebSocket 알림"""
        host_opponent = game.black_player if room.host == game.white_player else game.white_player
        guest_opponent = game.black_player if room.guest == game.white_player else game.white_player
        NotificationService.create_notification(
            user=room.host,
            type="match_found",
            title="매칭 완료",
            message=f"{host_opponent.nickname}님과 매칭되었습니다.",
            payload={
                "room_id": room.id,
                "game_id": game.id,
                "white_player": game.white_player.nickname,
                "black_player": game.black_player.nickname,
            },
        )
        NotificationService.create_notification(
            user=room.guest,
            type="match_found",
            title="매칭 완료",
            message=f"{guest_opponent.nickname}님과 매칭되었습니다.",
            payload={
                "room_id": room.id,
                "game_id": game.id,
                "white_player": game.white_player.nickname,
                "black_player": game.black_player.nickname,
            },
        )

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
