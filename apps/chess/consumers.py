import logging

from django.core.exceptions import ObjectDoesNotExist, PermissionDenied, ValidationError
from django.db import DatabaseError

from channels.generic.websocket import AsyncJsonWebsocketConsumer

from apps.accounts.services.presence_service import PresenceService
from apps.accounts.services.user_state_service import UserStateService
from apps.chess.consumer_data_mixins import GameConsumerDataMixin, LobbyConsumerDataMixin
from apps.chess.consumer_mixins import OnlineStatusMixin, WebSocketRateLimitMixin
from apps.chess.realtime_payloads import (
    REACTION_EMOJIS,
    build_chat_payload,
    build_guest_lobby_payload,
    build_lobby_user_payload,
)
from apps.chess.utils import check_profanity, get_profanity_warning

logger = logging.getLogger(__name__)
WS_CHAT_RATE_LIMIT = 12
WS_CHAT_RATE_WINDOW = 10
WS_REACTION_RATE_LIMIT = 30
WS_REACTION_RATE_WINDOW = 10


class ChessConsumer(
    GameConsumerDataMixin,
    OnlineStatusMixin,
    WebSocketRateLimitMixin,
    AsyncJsonWebsocketConsumer,
):
    """체스 게임 WebSocket Consumer"""

    async def connect(self):
        self.room_id = self.scope["url_route"]["kwargs"]["room_id"]
        self.player_group = f"chess_room_{self.room_id}"
        self.spectator_group = f"chess_room_{self.room_id}_spectators"
        user = self.scope["user"]

        if not user.is_authenticated:
            await self.close(code=4001)
            return

        access = await self._check_room_access(user)
        if access is None:
            await self.close(code=4003)
            return

        self.is_player = access["is_player"]
        self.room_type = access["room_type"]
        self.room_status = access["room_status"]
        group = self.player_group if self.is_player else self.spectator_group
        await self.channel_layer.group_add(group, self.channel_name)
        await self.accept()
        await self._set_user_online()
        await self._set_user_presence(
            self._presence_status_for_room(),
            scope=self._presence_scope_for_room(),
            room_id=int(self.room_id),
        )
        await self._send_recent_game_messages()
        if self.is_player:
            await self._clear_disconnect_marker()
        else:
            await self._add_spectator_presence(user)

    async def disconnect(self, close_code):
        await self._clear_user_presence()
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
            payload["pgn_append"] = {
                "san": result.move.san,
                "move_number": result.move.move_number,
                "player_color": result.move.player_color,
            }
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
        if UserStateService.is_suspended(self.scope["user"]):
            await self.send_json({"type": "error", "message": "정지된 계정입니다."})
            return False, None
        if UserStateService.is_muted(self.scope["user"]):
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
        if not await self._check_ws_rate_limit(
            "game_chat",
            limit=WS_CHAT_RATE_LIMIT,
            window_seconds=WS_CHAT_RATE_WINDOW,
            key_suffix="player",
        ):
            return
        valid, message = await self._validate_chat_message(content)
        if not valid:
            return
        message_id = self._new_chat_message_id()
        payload = build_chat_payload(
            scope="player",
            user=self.scope["user"],
            message=message,
            message_id=message_id,
            room_id=int(self.room_id),
        )
        await self._append_game_chat_history("player", payload)
        await self._broadcast_to_group(self.player_group, payload)

    async def _handle_spectator_chat(self, content):
        if self.is_player:
            await self.send_json(
                {"type": "error", "message": "플레이어는 관전자 채팅을 사용할 수 없습니다."}
            )
            return
        if not await self._check_ws_rate_limit(
            "spectator_chat",
            limit=WS_CHAT_RATE_LIMIT,
            window_seconds=WS_CHAT_RATE_WINDOW,
            key_suffix="spectator",
        ):
            return
        valid, message = await self._validate_chat_message(content)
        if not valid:
            return
        message_id = self._new_chat_message_id()
        payload = build_chat_payload(
            scope="spectator",
            user=self.scope["user"],
            message=message,
            message_id=message_id,
            room_id=int(self.room_id),
        )
        await self._append_game_chat_history("spectator", payload)
        await self._broadcast_to_group(self.spectator_group, payload)

    async def _handle_reaction(self, content):
        message_id = (content.get("message_id") or "").strip()
        emoji = (content.get("reaction") or "").strip()
        if not message_id or emoji not in REACTION_EMOJIS:
            return
        if not await self._check_ws_rate_limit(
            "game_reaction",
            limit=WS_REACTION_RATE_LIMIT,
            window_seconds=WS_REACTION_RATE_WINDOW,
            key_suffix="player" if self.is_player else "spectator",
        ):
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


class LobbyChatConsumer(
    LobbyConsumerDataMixin,
    OnlineStatusMixin,
    WebSocketRateLimitMixin,
    AsyncJsonWebsocketConsumer,
):
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
            await self._set_user_presence(
                PresenceService.STATUS_LOBBY,
                scope=f"{PresenceService.STATUS_LOBBY}:{self.channel_name}",
            )
            await self._add_to_lobby()

        await self._send_recent_messages()
        await self._send_lobby_users()

        if self.is_guest:
            await self._broadcast_guest_joined()
        else:
            await self._broadcast_user_joined()

    async def disconnect(self, close_code):
        await self._clear_user_presence()
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
            if UserStateService.is_suspended(self.scope["user"]):
                await self.send_json({"type": "error", "message": "정지된 계정입니다."})
                return
            if UserStateService.is_muted(self.scope["user"]):
                await self.send_json({"type": "error", "message": "채팅이 제한된 계정입니다."})
                return
            if not await self._check_ws_rate_limit(
                "lobby_chat",
                limit=WS_CHAT_RATE_LIMIT,
                window_seconds=WS_CHAT_RATE_WINDOW,
            ):
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

    async def _handle_lobby_reaction(self, content):
        if getattr(self, "is_guest", False):
            return
        message_id = content.get("message_id")
        emoji = (content.get("reaction") or "").strip()
        if not message_id or emoji not in REACTION_EMOJIS:
            return
        if not await self._check_ws_rate_limit(
            "lobby_reaction",
            limit=WS_REACTION_RATE_LIMIT,
            window_seconds=WS_REACTION_RATE_WINDOW,
        ):
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

    async def _send_lobby_users(self):
        """연결 시 현재 접속자 목록 전송"""
        users = await self._get_lobby_users()
        guests = await self._get_lobby_guests()
        all_users = users + guests
        await self.send_json({"type": "lobby_users", "users": all_users})

    async def _broadcast_user_joined(self):
        """유저 입장 브로드캐스트"""
        user = self.scope["user"]
        presence = await self._get_presence_payload(user.id)
        payload = {
            "type": "user_joined",
            "user": build_lobby_user_payload(user, presence=presence),
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

    async def _broadcast_guest_joined(self):
        """게스트 입장 브로드캐스트"""
        guest = self.scope.get("guest")
        if not guest:
            return

        payload = {
            "type": "user_joined",
            "user": build_guest_lobby_payload(guest),
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
