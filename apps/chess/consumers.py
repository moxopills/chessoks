from django.core.exceptions import ValidationError

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from apps.chess.services import GameService


class ChessConsumer(AsyncJsonWebsocketConsumer):
    """체스 게임 WebSocket Consumer"""

    async def connect(self):
        self.room_id = self.scope["url_route"]["kwargs"]["room_id"]
        self.group_name = f"chess_room_{self.room_id}"
        if not self.scope["user"].is_authenticated:
            await self.close(code=4001)
            return
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        action = content.get("action")
        if action == "move":
            await self._handle_move(content)
        elif action == "resign":
            await self._handle_resign(content)
        elif action == "draw":
            await self._handle_draw(content)
        else:
            await self.send_json({"type": "error", "message": "지원하지 않는 액션입니다."})

    async def _handle_move(self, content):
        try:
            game_id = content.get("game_id")
            uci = content.get("uci")
            promotion = content.get("promotion")
            result = await self._make_move(game_id, uci, promotion)
        except ValidationError as exc:
            await self.send_json({"type": "error", "message": self._format_error(exc)})
            return

        payload = self._game_payload(result.game)
        payload["type"] = "move"
        payload["move"] = result.move.san if result.move else None
        await self.channel_layer.group_send(
            self.group_name, {"type": "broadcast", "payload": payload}
        )

    async def _handle_resign(self, content):
        try:
            game_id = content.get("game_id")
            game = await self._resign(game_id)
        except ValidationError as exc:
            await self.send_json({"type": "error", "message": self._format_error(exc)})
            return

        payload = self._game_payload(game)
        payload["type"] = "game_end"
        await self.channel_layer.group_send(
            self.group_name, {"type": "broadcast", "payload": payload}
        )

    async def _handle_draw(self, content):
        try:
            game_id = content.get("game_id")
            game, status, player_color = await self._request_draw(game_id)
        except ValidationError as exc:
            await self.send_json({"type": "error", "message": self._format_error(exc)})
            return

        if status == "pending":
            payload = {"type": "draw_offer", "game_id": game_id, "from": player_color}
        else:
            payload = self._game_payload(game)
            payload["type"] = "game_end"

        await self.channel_layer.group_send(
            self.group_name, {"type": "broadcast", "payload": payload}
        )

    async def broadcast(self, event):
        await self.send_json(event["payload"])

    @database_sync_to_async
    def _make_move(self, game_id, uci, promotion):
        return GameService.make_move(game_id, self.scope["user"], uci, promotion)

    @database_sync_to_async
    def _resign(self, game_id):
        return GameService.resign(game_id, self.scope["user"])

    @database_sync_to_async
    def _request_draw(self, game_id):
        return GameService.request_draw(game_id, self.scope["user"])

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
