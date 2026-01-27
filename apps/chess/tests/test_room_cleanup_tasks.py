from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.accounts.tests.test_auth import User
from apps.chess.models import Room
from apps.chess.tasks import cleanup_inactive_rooms


class RoomCleanupTaskTestCase(TestCase):
    def setUp(self):
        self.host = User.objects.create_user(
            email="cleanup@test.com", nickname="정리", password="Pass123!"
        )
        self.guest = User.objects.create_user(
            email="cleanup2@test.com", nickname="정리2", password="Pass123!"
        )

    def test_cleanup_inactive_rooms(self):
        old_time = timezone.now() - timedelta(minutes=40)

        stale_room = Room.objects.create(host=self.host, room_type="quick", status="waiting")
        Room.objects.filter(id=stale_room.id).update(updated_at=old_time)

        abnormal_room = Room.objects.create(
            host=self.host, guest=self.guest, room_type="custom", status="playing"
        )
        Room.objects.filter(id=abnormal_room.id).update(updated_at=old_time, started_at=old_time)

        result = cleanup_inactive_rooms(stale_minutes=30)
        self.assertEqual(result["stale_deleted"], 1)
        self.assertEqual(result["abnormal_updated"], 1)

        self.assertFalse(Room.objects.filter(id=stale_room.id).exists())
        abnormal_room.refresh_from_db()
        self.assertEqual(abnormal_room.status, "finished")
