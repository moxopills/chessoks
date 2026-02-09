from django.test import TestCase

from apps.accounts.models import User
from apps.chess.utils import broadcast_spectator_event


class DummyChannelLayer:
    def __init__(self):
        self.calls = []

    async def group_send(self, group, message):
        self.calls.append((group, message))


class BroadcastSpectatorEventTestCase(TestCase):
    def test_broadcast_spectator_event_sends_to_player_and_spectator_groups(self):
        user = User.objects.create_user(
            email="spec@test.com", nickname="관전자", password="Pass123!"
        )
        layer = DummyChannelLayer()

        from unittest.mock import patch

        with patch("apps.chess.utils.get_channel_layer", return_value=layer):
            broadcast_spectator_event(42, user, "join")

        self.assertEqual(len(layer.calls), 2)
        groups = {call[0] for call in layer.calls}
        self.assertEqual(groups, {"chess_room_42", "chess_room_42_spectators"})

        for _, message in layer.calls:
            payload = message.get("payload", {})
            self.assertEqual(payload.get("type"), "spectator_event")
            self.assertEqual(payload.get("action"), "join")
            self.assertEqual(payload.get("user", {}).get("nickname"), "관전자")
