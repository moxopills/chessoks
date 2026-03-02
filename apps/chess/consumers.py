import logging
from uuid import uuid4

from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied, ValidationError
from django.db import DatabaseError, models
from django.utils import timezone

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from apps.accounts.models import User
from apps.accounts.services import OnlineStatusService
from apps.chess.models import LobbyMessage, LobbyMessageReaction, Room
from apps.chess.services import GameService
from apps.chess.utils import check_profanity, get_profanity_warning

logger = logging.getLogger(__name__)
REACTION_EMOJIS = {"👍", "👏"}


class OnlineStatusMixin:
    """온라인 상태 관리 Mixin (Heartbeat 방식)"""

    def _get_user_id(self):
        user = self.scope.get("user")
        return user.id if user and user.is_authenticated else None

    async def _handle_heartbeat(self, content=None):
        """heartbeat 처리 - TTL 갱신"""
        user_id = self._get_user_id()
        if user_id:
            OnlineStatusService.refresh(user_id)
            await self.send_json({"type": "heartbeat_ack"})

    async def _set_user_online(self):
        user_id = self._get_user_id()
        if user_id:
            OnlineStatusService.set_online(user_id)


class ChessConsumer(OnlineStatusMixin, AsyncJsonWebsocketConsumer):
    """체스 게임 WebSocket Consumer"""

    async def connect(self):
        self.room_id = self.scope["url_route"]["kwargs"]["room_id"]
        self.player_group = f"chess_room_{self.room_id}"
        self.spectator_group = f"chess_room_{self.room_id}_spectators"
        user = self.scope["user"]

        if not user.is_authenticated:
            await self.close(code=4001)
            return

        role = await self._check_room_access(user)
        if role is None:
            await self.close(code=4003)
            return

        self.is_player = role
        group = self.player_group if self.is_player else self.spectator_group
        await self.channel_layer.group_add(group, self.channel_name)
        await self.accept()
        await self._set_user_online()
        await self._send_recent_game_messages()
        if self.is_player:
            await self._clear_disconnect_marker()
        else:
            await self._add_spectator_presence(user)

    async def disconnect(self, close_code):
        if getattr(self, "is_player", False):
            await self._mark_disconnect()
        else:
            user = self.scope.get("user")
            if user and user.is_authenticated:
                await self._remove_spectator_presence(user)
        if hasattr(self, "player_group"):
            await self.channel_layer.group_discard(self.player_group, self.channel_name)
        if hasattr(self, "spectator_group"):
            await self.channel_layer.group_discard(self.spectator_group, self.channel_name)

    async def receive_json(self, content, **kwargs):
        try:
            action = content.get("action")
            handler = {
                "move": self._handle_move,
                "resign": self._handle_resign,
                "draw": self._handle_draw,
                "decline_draw": self._handle_decline_draw,
                "timeout": self._handle_timeout,
                "rematch": self._handle_rematch,
                "decline_rematch": self._handle_decline_rematch,
                "chat": self._handle_chat,
                "spectator_chat": self._handle_spectator_chat,
                "reaction": self._handle_reaction,
                "heartbeat": self._handle_heartbeat,
            }.get(action)

            if handler:
                await handler(content)
            else:
                await self.send_json({"type": "error", "message": "지원하지 않는 액션입니다."})
        except ValidationError as exc:
            await self.send_json({"type": "error", "message": self._format_error(exc)})
        except ObjectDoesNotExist:
            await self.send_json({"type": "error", "message": "게임을 찾을 수 없습니다."})
        except PermissionDenied as exc:
            await self.send_json({"type": "error", "message": str(exc) or "권한이 없습니다."})
        except DatabaseError as exc:
            logger.error("Database error in ChessConsumer: %s", exc)
            await self.send_json({"type": "error", "message": "데이터베이스 오류가 발생했습니다."})
        except Exception as exc:
            logger.exception("Unexpected error in ChessConsumer.receive_json: %s", exc)
            await self.send_json({"type": "error", "message": "처리 중 오류가 발생했습니다."})

    async def _handle_move(self, content):
        if not self.is_player:
            await self.send_json({"type": "error", "message": "관전자는 착수할 수 없습니다."})
            return
        result = await self._make_move(
            content.get("game_id"), content.get("uci"), content.get("promotion")
        )
        payload = self._game_payload(result.game)
        payload["type"] = "move"
        payload["move"] = result.move.san if result.move else None
        if result.move:
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
        if result.commentary:
            payload["commentary"] = result.commentary
            payload["commentary_level"] = result.commentary_level
            payload["commentary_color"] = result.commentary_color
        await self._broadcast(payload)

    async def _handle_resign(self, content):
        if not self.is_player:
            await self.send_json({"type": "error", "message": "관전자는 기권할 수 없습니다."})
            return
        game = await self._resign(content.get("game_id"))
        payload = self._game_payload(game)
        payload["type"] = "game_end"
        await self._broadcast(payload)

    async def _handle_timeout(self, content):
        """클라이언트에서 시간 초과 감지 시 호출"""
        game_id = content.get("game_id")
        game = await self._check_timeout(game_id)
        if game and game.result != "playing":
            payload = self._game_payload(game)
            payload["type"] = "game_end"
            await self._broadcast(payload)

    async def _handle_draw(self, content):
        if not self.is_player:
            await self.send_json(
                {"type": "error", "message": "관전자는 무승부 요청을 할 수 없습니다."}
            )
            return
        game_id = content.get("game_id")
        game, status, player_color = await self._request_draw(game_id)

        if status == "pending":
            payload = {"type": "draw_offer", "game_id": game_id, "from": player_color}
        else:
            payload = self._game_payload(game)
            payload["type"] = "game_end"
        await self._broadcast(payload)

    async def _handle_decline_draw(self, content):
        if not self.is_player:
            await self.send_json(
                {"type": "error", "message": "관전자는 무승부를 거절할 수 없습니다."}
            )
            return
        game_id = content.get("game_id")
        player_color = "white" if self.user.id == self.white_player_id else "black"
        payload = {"type": "draw_declined", "game_id": game_id, "from": player_color}
        await self._broadcast(payload)

    async def _handle_rematch(self, content):
        if not self.is_player:
            await self.send_json(
                {"type": "error", "message": "관전자는 리매치를 요청할 수 없습니다."}
            )
            return
        game_id = content.get("game_id")
        game, status, player_color = await self._request_rematch(game_id)

        if status == "pending":
            payload = {"type": "rematch_offer", "game_id": game_id, "from": player_color}
        else:
            payload = self._game_payload(game)
            payload["type"] = "rematch_created"
            payload["room_id"] = game.room_id
        await self._broadcast(payload)

    async def _handle_decline_rematch(self, content):
        if not self.is_player:
            await self.send_json(
                {"type": "error", "message": "관전자는 리매치를 거절할 수 없습니다."}
            )
            return
        game_id = content.get("game_id")
        declined, player_color = await self._decline_rematch(game_id)

        if declined:
            payload = {"type": "rematch_declined", "game_id": game_id, "from": player_color}
            await self._broadcast(payload)

    async def _validate_chat_message(self, content) -> tuple[bool, str | None]:
        """채팅 메시지 공통 검증"""
        if self.scope["user"].is_suspended:
            await self.send_json({"type": "error", "message": "정지된 계정입니다."})
            return False, None
        if self.scope["user"].is_muted:
            await self.send_json({"type": "error", "message": "채팅이 제한된 계정입니다."})
            return False, None
        message = (content.get("message") or "").strip()
        if not message:
            await self.send_json({"type": "error", "message": "메시지를 입력해주세요."})
            return False, None
        if len(message) > 500:
            await self.send_json(
                {"type": "error", "message": "메시지는 500자 이하로 입력해주세요."}
            )
            return False, None
        if check_profanity(message):
            await self.send_json({"type": "error", "message": get_profanity_warning()})
            return False, None
        return True, message

    async def _handle_chat(self, content):
        if not self.is_player:
            await self.send_json(
                {"type": "error", "message": "관전자는 플레이어 채팅을 사용할 수 없습니다."}
            )
            return
        # 게스트는 채팅 불가
        if getattr(self.scope["user"], "is_guest", False):
            await self.send_json(
                {"type": "error", "message": "게스트는 채팅을 이용할 수 없습니다."}
            )
            return
        valid, message = await self._validate_chat_message(content)
        if not valid:
            return
        message_id = self._new_chat_message_id()
        payload = {
            "type": "chat",
            "scope": "player",
            "message_id": message_id,
            "room_id": int(self.room_id),
            "user_id": self.scope["user"].id,
            "nickname": self.scope["user"].nickname,
            "avatar_url": self.scope["user"].avatar_url,
            "message": message,
            "sent_at": timezone.now().isoformat(),
            "reactions": {"👍": 0, "👏": 0},
            "my_reactions": [],
        }
        await self._append_game_chat_history("player", payload)
        await self._broadcast_to_group(self.player_group, payload)

    async def _handle_spectator_chat(self, content):
        if self.is_player:
            await self.send_json(
                {"type": "error", "message": "플레이어는 관전자 채팅을 사용할 수 없습니다."}
            )
            return
        valid, message = await self._validate_chat_message(content)
        if not valid:
            return
        message_id = self._new_chat_message_id()
        payload = {
            "type": "chat",
            "scope": "spectator",
            "message_id": message_id,
            "room_id": int(self.room_id),
            "user_id": self.scope["user"].id,
            "nickname": self.scope["user"].nickname,
            "avatar_url": self.scope["user"].avatar_url,
            "message": message,
            "sent_at": timezone.now().isoformat(),
            "reactions": {"👍": 0, "👏": 0},
            "my_reactions": [],
        }
        await self._append_game_chat_history("spectator", payload)
        await self._broadcast_to_group(self.spectator_group, payload)

    async def _handle_reaction(self, content):
        message_id = (content.get("message_id") or "").strip()
        emoji = (content.get("reaction") or "").strip()
        if not message_id or emoji not in REACTION_EMOJIS:
            return
        scope = "player" if self.is_player else "spectator"
        reaction_data = await self._toggle_game_reaction(scope, message_id, emoji)
        payload = {
            "type": "reaction_update",
            "scope": scope,
            "message_id": message_id,
            "reactions": reaction_data.get("reactions", {}),
        }
        target_group = self.player_group if self.is_player else self.spectator_group
        await self._broadcast_to_group(target_group, payload)

    async def _broadcast(self, payload):
        await self._broadcast_to_group(self.player_group, payload)
        await self._broadcast_to_group(self.spectator_group, payload)

    async def _broadcast_to_group(self, group_name, payload):
        await self.channel_layer.group_send(group_name, {"type": "broadcast", "payload": payload})

    async def broadcast(self, event):
        try:
            await self.send_json(event["payload"])
        except Exception:
            pass  # 연결 끊긴 클라이언트 무시

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
                message["reactions"] = message.get("reactions", {"👍": 0, "👏": 0})
                message["my_reactions"] = message.get("my_reactions", [])
            hydrated.append(message)
        return hydrated

    @database_sync_to_async
    def _toggle_game_reaction(self, scope: str, message_id: str, emoji: str) -> dict:
        key = self._reaction_key(int(self.room_id), message_id, scope)
        state = cache.get(key, {"👍": [], "👏": []})
        for e in REACTION_EMOJIS:
            state.setdefault(e, [])
        user_id = self.scope["user"].id
        users = set(state.get(emoji, []))
        if user_id in users:
            users.remove(user_id)
        else:
            users.add(user_id)
        state[emoji] = sorted(users)
        cache.set(key, state, timeout=60 * 60 * 6)
        return {
            "reactions": {e: len(state.get(e, [])) for e in REACTION_EMOJIS},
            "my_reactions": [e for e in REACTION_EMOJIS if user_id in set(state.get(e, []))],
        }

    @database_sync_to_async
    def _check_room_access(self, user) -> bool | None:
        """방 접근 권한 확인. 플레이어면 True, 관전자면 False, 접근 불가면 None"""
        try:
            room = Room.objects.only("host_id", "guest_id", "allow_spectators").get(pk=self.room_id)

            if room.host_id == user.id or room.guest_id == user.id:
                return True
            if room.allow_spectators:
                return False
            return None
        except Room.DoesNotExist:
            return None

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
        from django.core.cache import cache

        from apps.chess.models import Game

        # prefetch_related 대신 직접 Game 쿼리
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
        from django.core.cache import cache

        from apps.chess.models import Game

        # prefetch_related 대신 직접 Game 쿼리
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
    def _format_error(exc: ValidationError) -> str:
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
            "pgn": game.pgn,
            "current_turn": game.current_turn,
            "result": game.result,
            "white_time_remaining": game.white_time_remaining,
            "black_time_remaining": game.black_time_remaining,
            "turn_started_at": game.turn_started_at.isoformat() if game.turn_started_at else None,
        }


class LobbyChatConsumer(OnlineStatusMixin, AsyncJsonWebsocketConsumer):
    """로비 채팅 WebSocket Consumer"""

    group_name = "chess_lobby"
    lobby_users_key = "lobby_online_users"
    lobby_guests_key = "lobby_online_guests"

    async def connect(self):
        user = self.scope.get("user")
        guest = self.scope.get("guest")

        # 인증된 유저도 아니고 게스트도 아니면 거부
        is_authenticated = user and getattr(user, "is_authenticated", False)
        if not is_authenticated and not guest:
            await self.close(code=4001)
            return

        # 게스트 User인지 확인 (is_guest 속성 또는 guest 데이터 존재)
        self.is_guest = getattr(user, "is_guest", False) or (guest is not None)

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        if self.is_guest:
            await self._add_guest_to_lobby()
        else:
            await self._set_user_online()
            await self._add_to_lobby()

        await self._send_recent_messages()
        await self._send_lobby_users()

        if self.is_guest:
            await self._broadcast_guest_joined()
        else:
            await self._broadcast_user_joined()

    async def disconnect(self, close_code):
        if getattr(self, "is_guest", False):
            await self._remove_guest_from_lobby()
            await self._broadcast_guest_left()
        else:
            await self._remove_from_lobby()
            await self._broadcast_user_left()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        try:
            action = content.get("action")
            if action == "heartbeat":
                await self._handle_heartbeat(content)
                return
            if action == "reaction":
                await self._handle_lobby_reaction(content)
                return
            if action != "chat":
                await self.send_json({"type": "error", "message": "지원하지 않는 액션입니다."})
                return
            # 게스트는 채팅 불가
            if getattr(self, "is_guest", False):
                await self.send_json(
                    {"type": "error", "message": "게스트는 채팅을 이용할 수 없습니다."}
                )
                return
            if self.scope["user"].is_suspended:
                await self.send_json({"type": "error", "message": "정지된 계정입니다."})
                return
            if self.scope["user"].is_muted:
                await self.send_json({"type": "error", "message": "채팅이 제한된 계정입니다."})
                return

            message = (content.get("message") or "").strip()
            if not message:
                await self.send_json({"type": "error", "message": "메시지를 입력해주세요."})
                return
            if len(message) > 500:
                await self.send_json(
                    {"type": "error", "message": "메시지는 500자 이하로 입력해주세요."}
                )
                return
            if check_profanity(message):
                await self.send_json({"type": "error", "message": get_profanity_warning()})
                return

            saved = await self._save_lobby_message(message)
            payload = {
                "type": "chat",
                "scope": "lobby",
                "message_id": saved["id"],
                "user_id": self.scope["user"].id,
                "nickname": self.scope["user"].nickname,
                "avatar_url": self.scope["user"].avatar_url,
                "message": message,
                "sent_at": saved["created_at"],
                "reactions": {"👍": 0, "👏": 0},
                "my_reactions": [],
            }
            await self.channel_layer.group_send(
                self.group_name, {"type": "broadcast", "payload": payload}
            )
        except DatabaseError as exc:
            logger.error("Database error in LobbyChatConsumer: %s", exc)
            await self.send_json(
                {"type": "error", "message": "메시지 저장 중 오류가 발생했습니다."}
            )

    async def broadcast(self, event):
        try:
            await self.send_json(event["payload"])
        except Exception:
            pass

    @database_sync_to_async
    def _save_lobby_message(self, message: str) -> dict:
        msg = LobbyMessage.objects.create(user=self.scope["user"], message=message)
        return {"id": msg.id, "created_at": msg.created_at.isoformat()}

    async def _handle_lobby_reaction(self, content):
        if getattr(self, "is_guest", False):
            return
        message_id = content.get("message_id")
        emoji = (content.get("reaction") or "").strip()
        if not message_id or emoji not in REACTION_EMOJIS:
            return
        reaction_data = await self._toggle_lobby_reaction(int(message_id), emoji)
        if reaction_data is None:
            return
        payload = {
            "type": "reaction_update",
            "scope": "lobby",
            "message_id": int(message_id),
            "reactions": reaction_data.get("reactions", {}),
        }
        await self.channel_layer.group_send(
            self.group_name, {"type": "broadcast", "payload": payload}
        )

    async def _send_recent_messages(self):
        """연결 시 최근 메시지 전송"""
        messages = await self._get_recent_messages()
        if messages:
            await self.send_json({"type": "recent_messages", "messages": messages})

    @database_sync_to_async
    def _get_recent_messages(self, limit: int = 100) -> list:
        """최근 로비 메시지 조회"""
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
        """로비 접속자 목록에 추가"""
        from django.core.cache import cache

        user = self.scope["user"]
        users = cache.get(self.lobby_users_key, {})
        rank_tier = getattr(getattr(user, "stats", None), "rank_tier", "Junior")
        users[str(user.id)] = {
            "id": user.id,
            "nickname": user.nickname,
            "avatar_url": user.avatar_url,
            "rank_tier": rank_tier,
        }
        cache.set(self.lobby_users_key, users, timeout=3600)

    @database_sync_to_async
    def _remove_from_lobby(self):
        """로비 접속자 목록에서 제거"""
        from django.core.cache import cache

        user = self.scope["user"]
        users = cache.get(self.lobby_users_key, {})
        users.pop(str(user.id), None)
        cache.set(self.lobby_users_key, users, timeout=3600)

    @database_sync_to_async
    def _get_lobby_users(self) -> list:
        """온라인 접속자 목록 조회 - 게스트 제외"""
        online_ids = OnlineStatusService.list_online_ids()
        if not online_ids:
            return []
        queryset = User.objects.select_related("stats").filter(id__in=online_ids, is_guest=False)
        user_map = {user.id: user for user in queryset}
        users = []
        for user_id in online_ids:
            user = user_map.get(user_id)
            if not user:
                continue
            users.append(
                {
                    "id": user.id,
                    "nickname": user.nickname,
                    "avatar_url": user.avatar_url,
                    "rank_tier": getattr(getattr(user, "stats", None), "rank_tier", "Junior"),
                    "nickname_color": getattr(getattr(user, "stats", None), "nickname_color", ""),
                    "profile_border": getattr(getattr(user, "stats", None), "profile_border", ""),
                }
            )
        return users

    async def _send_lobby_users(self):
        """연결 시 현재 접속자 목록 전송"""
        users = await self._get_lobby_users()
        guests = await self._get_lobby_guests()
        all_users = users + guests
        await self.send_json({"type": "lobby_users", "users": all_users})

    async def _broadcast_user_joined(self):
        """유저 입장 브로드캐스트"""
        user = self.scope["user"]
        payload = {
            "type": "user_joined",
            "user": {
                "id": user.id,
                "nickname": user.nickname,
                "avatar_url": user.avatar_url,
                "rank_tier": getattr(getattr(user, "stats", None), "rank_tier", "Junior"),
                "nickname_color": getattr(getattr(user, "stats", None), "nickname_color", ""),
                "profile_border": getattr(getattr(user, "stats", None), "profile_border", ""),
            },
        }
        await self.channel_layer.group_send(
            self.group_name, {"type": "broadcast", "payload": payload}
        )

    async def _broadcast_user_left(self):
        """유저 퇴장 브로드캐스트"""
        user = self.scope["user"]
        payload = {
            "type": "user_left",
            "user_id": user.id,
        }
        await self.channel_layer.group_send(
            self.group_name, {"type": "broadcast", "payload": payload}
        )

    async def _broadcast_lobby_users(self):
        users = await self._get_lobby_users()
        guests = await self._get_lobby_guests()
        all_users = users + guests
        await self.channel_layer.group_send(
            self.group_name,
            {"type": "broadcast", "payload": {"type": "lobby_users", "users": all_users}},
        )

    # === 게스트 관련 메서드 ===

    @database_sync_to_async
    def _add_guest_to_lobby(self):
        """게스트를 로비 접속자 목록에 추가"""
        from django.core.cache import cache

        guest = self.scope.get("guest")
        if not guest:
            return

        guests = cache.get(self.lobby_guests_key, {})
        guests[guest["token"]] = {
            "id": f"guest_{guest['token'][:8]}",
            "nickname": guest["display_name"],
            "avatar_url": None,
            "rank_tier": None,
            "is_guest": True,
        }
        cache.set(self.lobby_guests_key, guests, timeout=3600)

    @database_sync_to_async
    def _remove_guest_from_lobby(self):
        """게스트를 로비 접속자 목록에서 제거"""
        from django.core.cache import cache

        guest = self.scope.get("guest")
        if not guest:
            return

        guests = cache.get(self.lobby_guests_key, {})
        guests.pop(guest["token"], None)
        cache.set(self.lobby_guests_key, guests, timeout=3600)

    @database_sync_to_async
    def _get_lobby_guests(self) -> list:
        """로비의 게스트 목록 조회"""
        from django.core.cache import cache

        guests = cache.get(self.lobby_guests_key, {})
        return list(guests.values())

    async def _broadcast_guest_joined(self):
        """게스트 입장 브로드캐스트"""
        guest = self.scope.get("guest")
        if not guest:
            return

        payload = {
            "type": "user_joined",
            "user": {
                "id": f"guest_{guest['token'][:8]}",
                "nickname": guest["display_name"],
                "avatar_url": None,
                "rank_tier": None,
                "is_guest": True,
            },
        }
        await self.channel_layer.group_send(
            self.group_name, {"type": "broadcast", "payload": payload}
        )

    async def _broadcast_guest_left(self):
        """게스트 퇴장 브로드캐스트"""
        guest = self.scope.get("guest")
        if not guest:
            return

        payload = {
            "type": "user_left",
            "user_id": f"guest_{guest['token'][:8]}",
        }
        await self.channel_layer.group_send(
            self.group_name, {"type": "broadcast", "payload": payload}
        )
