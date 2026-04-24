from uuid import uuid4

from django.core.cache import cache
from django.db import models
from django.utils import timezone

from channels.db import database_sync_to_async

from apps.accounts.models import User
from apps.accounts.services.online_status_service import OnlineStatusService
from apps.accounts.services.presence_service import PresenceService
from apps.accounts.services.user_stats_service import UserStatsService
from apps.chess.models import LobbyMessage, LobbyMessageReaction, Room
from apps.chess.realtime_payloads import (
    REACTION_EMOJIS,
    build_guest_lobby_payload,
    build_lobby_user_payload,
    empty_reactions,
)
from apps.chess.services import GameService


class GameConsumerDataMixin:
    @staticmethod
    def _new_chat_message_id() -> str:
        return uuid4().hex[:16]

    @staticmethod
    def _history_key(room_id: int, scope: str) -> str:
        return f"chess:chat:history:{room_id}:{scope}"

    @staticmethod
    def _reaction_key(room_id: int, message_id: str, scope: str) -> str:
        return f"chess:chat:react:{room_id}:{scope}:{message_id}"

    async def _send_recent_game_messages(self) -> None:
        scope = "player" if self.is_player else "spectator"
        messages = await self._get_game_chat_history(scope)
        if messages:
            await self.send_json({"type": "recent_messages", "messages": messages})

    @database_sync_to_async
    def _append_game_chat_history(self, scope: str, payload: dict) -> None:
        key = self._history_key(int(self.room_id), scope)
        history = cache.get(key, [])
        history.append(payload)
        if len(history) > 120:
            history = history[-120:]
        cache.set(key, history, timeout=60 * 60 * 6)

    @database_sync_to_async
    def _get_game_chat_history(self, scope: str) -> list[dict]:
        key = self._history_key(int(self.room_id), scope)
        history = cache.get(key, [])
        hydrated: list[dict] = []
        for item in history:
            message = dict(item)
            message_id = message.get("message_id")
            if message_id:
                react_key = self._reaction_key(int(self.room_id), str(message_id), scope)
                state = cache.get(react_key, {"👍": [], "👏": []})
                message["reactions"] = {
                    "👍": len(state.get("👍", [])),
                    "👏": len(state.get("👏", [])),
                }
                current_user_id = self.scope["user"].id
                message["my_reactions"] = [
                    emoji
                    for emoji in REACTION_EMOJIS
                    if current_user_id in set(state.get(emoji, []))
                ]
            else:
                message["reactions"] = message.get("reactions", empty_reactions())
                message["my_reactions"] = message.get("my_reactions", [])
            hydrated.append(message)
        return hydrated

    @database_sync_to_async
    def _toggle_game_reaction(self, scope: str, message_id: str, emoji: str) -> dict:
        key = self._reaction_key(int(self.room_id), message_id, scope)
        state = cache.get(key, {"👍": [], "👏": []})
        for reaction_emoji in REACTION_EMOJIS:
            state.setdefault(reaction_emoji, [])
        user_id = self.scope["user"].id
        users = set(state.get(emoji, []))
        if user_id in users:
            users.remove(user_id)
        else:
            users.add(user_id)
        state[emoji] = sorted(users)
        cache.set(key, state, timeout=60 * 60 * 6)
        return {
            "reactions": {
                reaction_emoji: len(state.get(reaction_emoji, []))
                for reaction_emoji in REACTION_EMOJIS
            },
            "my_reactions": [
                reaction_emoji
                for reaction_emoji in REACTION_EMOJIS
                if user_id in set(state.get(reaction_emoji, []))
            ],
        }

    @database_sync_to_async
    def _check_room_access(self, user) -> dict | None:
        try:
            room = Room.objects.only(
                "host_id", "guest_id", "allow_spectators", "room_type", "status"
            ).get(pk=self.room_id)
            if room.host_id == user.id or room.guest_id == user.id:
                return {
                    "is_player": True,
                    "room_type": room.room_type,
                    "room_status": room.status,
                }
            if room.allow_spectators:
                return {
                    "is_player": False,
                    "room_type": room.room_type,
                    "room_status": room.status,
                }
            return None
        except Room.DoesNotExist:
            return None

    def _presence_status_for_room(self) -> str:
        if not getattr(self, "is_player", False):
            return PresenceService.STATUS_SPECTATING
        if getattr(self, "room_status", "playing") != "playing":
            return PresenceService.STATUS_ROOM_WAITING
        room_type = getattr(self, "room_type", "")
        if room_type == "random":
            return PresenceService.STATUS_COMPETITIVE
        if room_type == "quick":
            return PresenceService.STATUS_QUICK
        if str(room_type).startswith("ai_"):
            return PresenceService.STATUS_AI_PLAYING
        return PresenceService.STATUS_PLAYING

    def _presence_scope_for_room(self) -> str:
        role = "player" if getattr(self, "is_player", False) else "spectator"
        return f"{self._presence_status_for_room()}:room-{self.room_id}:{role}:{self.channel_name}"

    @database_sync_to_async
    def _add_spectator_presence(self, user) -> None:
        room = Room.objects.filter(pk=self.room_id).first()
        if room:
            room.spectators.add(user)

    @database_sync_to_async
    def _remove_spectator_presence(self, user) -> None:
        room = Room.objects.filter(pk=self.room_id).first()
        if room:
            room.spectators.remove(user)

    @database_sync_to_async
    def _mark_disconnect(self) -> None:
        from apps.chess.models import Game

        game = (
            Game.objects.filter(room_id=self.room_id, result=Game.Status.PLAYING)
            .only("id", "white_player_id", "black_player_id")
            .first()
        )
        if not game:
            return
        user_id = self.scope["user"].id
        color = (
            "white"
            if game.white_player_id == user_id
            else "black" if game.black_player_id == user_id else None
        )
        if not color:
            return
        cache.set(
            GameService._cache_key("disconnect", game.id, color),
            timezone.now().timestamp(),
            timeout=GameService.DISCONNECT_GRACE_SECONDS,
        )

    @database_sync_to_async
    def _clear_disconnect_marker(self) -> None:
        from apps.chess.models import Game

        game = (
            Game.objects.filter(room_id=self.room_id, result=Game.Status.PLAYING)
            .only("id", "white_player_id", "black_player_id")
            .first()
        )
        if not game:
            return
        user_id = self.scope["user"].id
        color = (
            "white"
            if game.white_player_id == user_id
            else "black" if game.black_player_id == user_id else None
        )
        if not color:
            return
        cache.delete(GameService._cache_key("disconnect", game.id, color))

    @database_sync_to_async
    def _make_move(self, game_id, uci, promotion):
        return GameService.make_move(game_id, self.scope["user"], uci, promotion)

    @database_sync_to_async
    def _resign(self, game_id):
        return GameService.resign(game_id, self.scope["user"])

    @database_sync_to_async
    def _request_draw(self, game_id):
        return GameService.request_draw(game_id, self.scope["user"])

    @database_sync_to_async
    def _request_rematch(self, game_id):
        return GameService.request_rematch(game_id, self.scope["user"])

    @database_sync_to_async
    def _decline_rematch(self, game_id):
        return GameService.decline_rematch(game_id, self.scope["user"])

    @database_sync_to_async
    def _check_timeout(self, game_id):
        return GameService.check_and_apply_timeout(game_id)

    @staticmethod
    def _format_error(exc) -> str:
        detail = getattr(exc, "detail", None)
        if isinstance(detail, (list, tuple)) and detail:
            return str(detail[0])
        if isinstance(detail, dict):
            first = next(iter(detail.values()), "")
            if isinstance(first, (list, tuple)) and first:
                return str(first[0])
            return str(first)
        return str(exc)

    @staticmethod
    def _game_payload(game):
        return {
            "game_id": game.id,
            "fen": game.fen,
            "current_turn": game.current_turn,
            "result": game.result,
            "white_time_remaining": game.white_time_remaining,
            "black_time_remaining": game.black_time_remaining,
            "turn_started_at": game.turn_started_at.isoformat() if game.turn_started_at else None,
        }


class LobbyConsumerDataMixin:
    @database_sync_to_async
    def _save_lobby_message(self, message: str) -> dict:
        msg = LobbyMessage.objects.create(user=self.scope["user"], message=message)
        return {"id": msg.id, "created_at": msg.created_at.isoformat()}

    @database_sync_to_async
    def _get_recent_messages(self, limit: int = 100) -> list:
        messages = LobbyMessage.objects.select_related("user").order_by("-created_at")[:limit]
        message_ids = [msg.id for msg in messages]
        reaction_rows = (
            LobbyMessageReaction.objects.filter(message_id__in=message_ids)
            .values("message_id", "emoji")
            .annotate(count=models.Count("id"))
        )
        current_user_id = self.scope["user"].id
        my_rows = LobbyMessageReaction.objects.filter(
            message_id__in=message_ids, user_id=current_user_id
        ).values("message_id", "emoji")
        reaction_map = {msg_id: {"👍": 0, "👏": 0} for msg_id in message_ids}
        my_reaction_map = {msg_id: [] for msg_id in message_ids}
        for row in reaction_rows:
            if row["emoji"] in REACTION_EMOJIS:
                reaction_map.setdefault(row["message_id"], {"👍": 0, "👏": 0})[row["emoji"]] = row[
                    "count"
                ]
        for row in my_rows:
            emoji = row.get("emoji")
            if emoji in REACTION_EMOJIS:
                my_reaction_map.setdefault(row["message_id"], []).append(emoji)
        return [
            {
                "type": "chat",
                "scope": "lobby",
                "message_id": msg.id,
                "user_id": msg.user_id,
                "nickname": msg.user.nickname,
                "avatar_url": msg.user.avatar_url,
                "message": msg.message,
                "sent_at": msg.created_at.isoformat(),
                "reactions": reaction_map.get(msg.id, {"👍": 0, "👏": 0}),
                "my_reactions": my_reaction_map.get(msg.id, []),
            }
            for msg in reversed(messages)
        ]

    @database_sync_to_async
    def _toggle_lobby_reaction(self, message_id: int, emoji: str) -> dict | None:
        message = LobbyMessage.objects.filter(id=message_id).first()
        if not message:
            return None
        user = self.scope["user"]
        existing = LobbyMessageReaction.objects.filter(
            message_id=message_id, user_id=user.id, emoji=emoji
        ).first()
        if existing:
            existing.delete()
        else:
            LobbyMessageReaction.objects.create(message=message, user=user, emoji=emoji)
        rows = (
            LobbyMessageReaction.objects.filter(message_id=message_id)
            .values("emoji")
            .annotate(count=models.Count("id"))
        )
        reactions = {"👍": 0, "👏": 0}
        for row in rows:
            if row["emoji"] in REACTION_EMOJIS:
                reactions[row["emoji"]] = row["count"]
        my_reactions = list(
            LobbyMessageReaction.objects.filter(message_id=message_id, user_id=user.id).values_list(
                "emoji", flat=True
            )
        )
        return {"reactions": reactions, "my_reactions": my_reactions}

    @database_sync_to_async
    def _add_to_lobby(self):
        user = self.scope["user"]
        users = cache.get(self.lobby_users_key, {})
        rank_tier = UserStatsService.get_rank_tier(getattr(user, "stats", None))
        users[str(user.id)] = {
            "id": user.id,
            "nickname": user.nickname,
            "avatar_url": user.avatar_url,
            "rank_tier": rank_tier,
        }
        cache.set(self.lobby_users_key, users, timeout=3600)

    @database_sync_to_async
    def _remove_from_lobby(self):
        user = self.scope["user"]
        users = cache.get(self.lobby_users_key, {})
        users.pop(str(user.id), None)
        cache.set(self.lobby_users_key, users, timeout=3600)

    @database_sync_to_async
    def _get_lobby_users(self) -> list:
        online_ids = OnlineStatusService.list_online_ids()
        if not online_ids:
            return []
        presence_map = PresenceService.bulk_presence(online_ids)
        queryset = (
            User.objects.select_related("stats")
            .only(
                "id",
                "nickname",
                "avatar_url",
                "stats__rating",
                "stats__competitive_games_played",
                "stats__nickname_color",
                "stats__profile_border",
            )
            .filter(id__in=online_ids, is_guest=False)
        )
        user_map = {user.id: user for user in queryset}
        users = []
        for user_id in online_ids:
            user = user_map.get(user_id)
            if not user:
                continue
            users.append(build_lobby_user_payload(user, presence=presence_map.get(user.id, {})))
        return users

    @database_sync_to_async
    def _get_presence_payload(self, user_id: int) -> dict:
        return PresenceService.get_presence(user_id)

    @database_sync_to_async
    def _add_guest_to_lobby(self):
        guest = self.scope.get("guest")
        if not guest:
            return
        guests = cache.get(self.lobby_guests_key, {})
        guests[guest["token"]] = build_guest_lobby_payload(guest)
        cache.set(self.lobby_guests_key, guests, timeout=3600)

    @database_sync_to_async
    def _remove_guest_from_lobby(self):
        guest = self.scope.get("guest")
        if not guest:
            return
        guests = cache.get(self.lobby_guests_key, {})
        guests.pop(guest["token"], None)
        cache.set(self.lobby_guests_key, guests, timeout=3600)

    @database_sync_to_async
    def _get_lobby_guests(self) -> list:
        guests = cache.get(self.lobby_guests_key, {})
        return list(guests.values())
