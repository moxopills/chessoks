from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TransactionTestCase, override_settings

from asgiref.sync import async_to_sync
from channels.testing import WebsocketCommunicator

from apps.chess.consumers import ChessConsumer
from apps.chess.models import Game, Room

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
