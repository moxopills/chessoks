from django.db import models, transaction
from django.utils import timezone

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from rest_framework.exceptions import ValidationError

from apps.accounts.models import UserStats
from apps.accounts.services.user_state_service import UserStateService
from apps.chess.models import Game, Room
from apps.chess.utils import assign_colors, broadcast_room_removed, broadcast_room_update
from apps.notifications.services import NotificationService


class MatchmakingService:
    """빠른 대전 매칭 서비스"""

    QUICK_ROOM_TYPE = "quick"
    RANDOM_ROOM_TYPE = "random"
    MATCH_ROOM_TYPES = {QUICK_ROOM_TYPE, RANDOM_ROOM_TYPE}
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
        return MatchmakingService._match(
            user,
            room_type=MatchmakingService.QUICK_ROOM_TYPE,
            title="경쟁전",
            rating_based=True,
        )

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
        return MatchmakingService._cancel_match(user, MatchmakingService.QUICK_ROOM_TYPE)

    @staticmethod
    @transaction.atomic
    def random_match(user) -> tuple[Room, Game | None, str]:
        """랜덤 대전 매칭 (레이팅 영향 없음)"""
        return MatchmakingService._match(
            user,
            room_type=MatchmakingService.RANDOM_ROOM_TYPE,
            title="랜덤 대전",
            rating_based=False,
        )

    @staticmethod
    def cancel_random_match(user) -> bool:
        """대기 중인 랜덤 대전 취소"""
        return MatchmakingService._cancel_match(user, MatchmakingService.RANDOM_ROOM_TYPE)

    @staticmethod
    def _match(
        user,
        *,
        room_type: str,
        title: str,
        rating_based: bool,
    ) -> tuple[Room, Game | None, str]:
        MatchmakingService._ensure_available(user)
        playing = MatchmakingService._find_playing_room(user, room_type)
        if playing is not None:
            return playing, MatchmakingService._ensure_game(playing), "matched"

        existing = MatchmakingService._find_existing_waiting_room(user, room_type)

        room = None
        if rating_based:
            stats, _ = UserStats.objects.get_or_create(user=user)
            room = MatchmakingService._find_best_room(user, stats.rating)
        else:
            room = MatchmakingService._find_first_room(user, room_type)

        if room is None:
            if existing is not None:
                return existing, None, "waiting"
            room = MatchmakingService._create_waiting_room(user, room_type, title)
            return room, None, "waiting"

        room, game = MatchmakingService._start_match(room, user, existing)
        return room, game, "matched"

    @staticmethod
    def _ensure_available(user) -> None:
        if UserStateService.is_suspended(user):
            raise ValidationError("정지된 계정입니다.")

    @staticmethod
    def _find_playing_room(user, room_type: str) -> Room | None:
        return (
            Room.objects.select_for_update(skip_locked=True)
            .filter(room_type=room_type, status="playing")
            .filter(models.Q(host=user) | models.Q(guest=user))
            .prefetch_related("games")
            .first()
        )

    @staticmethod
    def _find_existing_waiting_room(user, room_type: str) -> Room | None:
        return (
            Room.objects.select_for_update(skip_locked=True)
            .filter(room_type=room_type, host=user, status="waiting", guest__isnull=True)
            .first()
        )

    @staticmethod
    def _find_first_room(user, room_type: str) -> Room | None:
        return (
            Room.objects.select_for_update(skip_locked=True)
            .filter(room_type=room_type, status="waiting", guest__isnull=True)
            .exclude(host=user)
            .order_by("created_at")
            .first()
        )

    @staticmethod
    def _create_waiting_room(user, room_type: str, title: str) -> Room:
        room = Room.objects.create(
            room_type=room_type,
            title=title,
            host=user,
            status="waiting",
            is_private=False,
        )
        broadcast_room_update(room)
        return room

    @staticmethod
    def _ensure_game(room: Room) -> Game | None:
        game = room.games.filter(result="playing").only("id").first()
        if game is not None:
            return game
        if not (room.host_id and room.guest_id):
            return None
        white_player, black_player = assign_colors(room.host, room.guest)
        return Game.objects.create(room=room, white_player=white_player, black_player=black_player)

    @staticmethod
    def _start_match(room: Room, user, existing: Room | None) -> tuple[Room, Game]:
        room.guest = user
        room.status = "playing"
        room.started_at = timezone.now()
        room.save(update_fields=["guest", "status", "started_at"])
        broadcast_room_update(room)

        if existing is not None and existing.id != room.id:
            existing_id = existing.id
            existing.delete()
            broadcast_room_removed(existing_id)

        white_player, black_player = assign_colors(room.host, room.guest)
        game = Game.objects.create(room=room, white_player=white_player, black_player=black_player)
        MatchmakingService._notify_match(room, game)
        return room, game

    @staticmethod
    def _cancel_match(user, room_type: str) -> bool:
        room = (
            Room.objects.filter(
                room_type=room_type, host=user, status="waiting", guest__isnull=True
            )
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
