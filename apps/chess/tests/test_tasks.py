from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.chess.models import LobbyMessage
from apps.chess.tasks import cleanup_lobby_messages

User = get_user_model()


class LobbyMessageCleanupTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="cleanup@test.com", nickname="정리", password="Pass123!"
        )

    def test_cleanup_lobby_messages(self):
        old_msg = LobbyMessage.objects.create(user=self.user, message="old")
        LobbyMessage.objects.filter(pk=old_msg.pk).update(
            created_at=timezone.now() - timedelta(days=4)
        )
        LobbyMessage.objects.create(user=self.user, message="new")

        deleted = cleanup_lobby_messages(retention_days=3)
        self.assertEqual(deleted, 1)
        self.assertEqual(LobbyMessage.objects.count(), 1)
