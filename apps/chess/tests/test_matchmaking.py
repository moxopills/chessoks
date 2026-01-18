from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.chess.models import Room
from apps.chess.services import MatchmakingService

User = get_user_model()


class MatchmakingServiceTestCase(TestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(
            email="m1@test.com", nickname="매칭1", password="Pass123!"
        )
        self.user2 = User.objects.create_user(
            email="m2@test.com", nickname="매칭2", password="Pass123!"
        )

    def test_first_user_creates_waiting_room(self):
        room, game, status = MatchmakingService.quick_match(self.user1)
        self.assertEqual(status, "waiting")
        self.assertIsNone(game)
        self.assertEqual(room.status, "waiting")

    def test_second_user_matches_existing_room(self):
        MatchmakingService.quick_match(self.user1)
        room, game, status = MatchmakingService.quick_match(self.user2)
        self.assertEqual(status, "matched")
        self.assertEqual(room.status, "playing")
        self.assertIsNotNone(game)
        self.assertEqual(game.room_id, room.id)

    def test_rating_band_prefers_closest_room(self):
        other = User.objects.create_user(email="m3@test.com", nickname="매칭3", password="Pass123!")
        self.user1.stats.rating = 1200
        self.user1.stats.save(update_fields=["rating"])
        self.user2.stats.rating = 1600
        self.user2.stats.save(update_fields=["rating"])
        other.stats.rating = 1300
        other.stats.save(update_fields=["rating"])

        Room.objects.create(room_type="quick", host=self.user2, status="waiting", is_private=False)
        Room.objects.create(room_type="quick", host=other, status="waiting", is_private=False)
        room, _, status = MatchmakingService.quick_match(self.user1)
        self.assertEqual(status, "matched")
        self.assertEqual(room.host_id, other.id)
