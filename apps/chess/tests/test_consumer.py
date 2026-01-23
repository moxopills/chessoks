from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TransactionTestCase, override_settings

from asgiref.sync import async_to_sync
from channels.testing import WebsocketCommunicator

from apps.chess.consumers import ChessConsumer, LobbyChatConsumer
from apps.chess.models import Game, LobbyMessage, Room

User = get_user_model()


@override_settings(CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}})
class ChessConsumerTestCase(TransactionTestCase):
    def setUp(self):
        self.white = User.objects.create_user(
            email="white5@test.com", nickname="화이트5", password="Pass123!"
        )
        self.black = User.objects.create_user(
            email="black5@test.com", nickname="블랙5", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.white, guest=self.black)
        self.room.status = "playing"
        self.room.save(update_fields=["status"])
        self.game = Game.objects.create(
            room=self.room, white_player=self.white, black_player=self.black
        )

    def _communicator(self, user):
        communicator = WebsocketCommunicator(ChessConsumer.as_asgi(), f"/ws/chess/{self.room.id}/")
        communicator.scope["user"] = user
        communicator.scope["url_route"] = {"kwargs": {"room_id": str(self.room.id)}}
        return communicator

    def test_rejects_unauthenticated(self):
        async def _run():
            communicator = self._communicator(AnonymousUser())
            connected, _ = await communicator.connect()
            await communicator.disconnect()
            return connected

        connected = async_to_sync(_run)()
        self.assertFalse(connected)

    def test_move_broadcast(self):
        async def _run():
            communicator = self._communicator(self.white)
            connected, _ = await communicator.connect()
            if not connected:
                return None

            await communicator.send_json_to(
                {"action": "move", "game_id": self.game.id, "uci": "e2e4"}
            )
            message = await communicator.receive_json_from()
            await communicator.disconnect()
            return message

        message = async_to_sync(_run)()
        self.assertIsNotNone(message)
        self.assertEqual(message["type"], "move")
        self.assertEqual(message["game_id"], self.game.id)

    def test_rematch_offer(self):
        self.game.result = "checkmate_black"
        self.game.save(update_fields=["result"])

        async def _run():
            communicator = self._communicator(self.white)
            connected, _ = await communicator.connect()
            if not connected:
                return None

            await communicator.send_json_to({"action": "rematch", "game_id": self.game.id})
            message = await communicator.receive_json_from()
            await communicator.disconnect()
            return message

        message = async_to_sync(_run)()
        self.assertIsNotNone(message)
        self.assertEqual(message["type"], "rematch_offer")

    def test_game_chat_broadcast(self):
        async def _run():
            communicator = self._communicator(self.white)
            connected, _ = await communicator.connect()
            if not connected:
                return None

            await communicator.send_json_to({"action": "chat", "message": "안녕하세요"})
            message = await communicator.receive_json_from()
            await communicator.disconnect()
            return message

        message = async_to_sync(_run)()
        self.assertIsNotNone(message)
        self.assertEqual(message["type"], "chat")
        self.assertEqual(message["scope"], "player")
        self.assertEqual(message["room_id"], self.room.id)

    def test_spectator_chat_broadcast(self):
        spectator = User.objects.create_user(
            email="spectator@test.com", nickname="관전자", password="Pass123!"
        )

        async def _run():
            communicator = self._communicator(spectator)
            connected, _ = await communicator.connect()
            if not connected:
                return None

            await communicator.send_json_to({"action": "spectator_chat", "message": "관전 채팅"})
            message = await communicator.receive_json_from()
            await communicator.disconnect()
            return message

        message = async_to_sync(_run)()
        self.assertIsNotNone(message)
        self.assertEqual(message["type"], "chat")
        self.assertEqual(message["scope"], "spectator")


@override_settings(CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}})
class LobbyChatConsumerTestCase(TransactionTestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="lobby@test.com", nickname="로비", password="Pass123!"
        )

    def _communicator(self, user):
        communicator = WebsocketCommunicator(LobbyChatConsumer.as_asgi(), "/ws/lobby/")
        communicator.scope["user"] = user
        communicator.scope["url_route"] = {"kwargs": {}}
        return communicator

    def test_lobby_chat_broadcast(self):
        async def _run():
            communicator = self._communicator(self.user)
            connected, _ = await communicator.connect()
            if not connected:
                return None

            await communicator.send_json_to({"action": "chat", "message": "로비 채팅"})
            message = await communicator.receive_json_from()
            await communicator.disconnect()
            return message

        message = async_to_sync(_run)()
        self.assertIsNotNone(message)
        self.assertEqual(message["type"], "chat")
        self.assertEqual(message["scope"], "lobby")
        self.assertEqual(LobbyMessage.objects.count(), 1)
        saved = LobbyMessage.objects.first()
        self.assertEqual(saved.user_id, self.user.id)
        self.assertEqual(saved.message, "로비 채팅")
