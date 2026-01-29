from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

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

    def test_repeated_quick_match_does_not_create_duplicate_room(self):
        room1, game1, status1 = MatchmakingService.quick_match(self.user1)
        room2, game2, status2 = MatchmakingService.quick_match(self.user1)

        self.assertEqual(status1, "waiting")
        self.assertEqual(status2, "waiting")
        self.assertIsNone(game1)
        self.assertIsNone(game2)
        self.assertEqual(room1.id, room2.id)
        self.assertEqual(
            Room.objects.filter(room_type="quick", host=self.user1, status="waiting").count(), 1
        )

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

    def test_wait_time_expands_rating_band(self):
        self.user1.stats.rating = 1200
        self.user1.stats.save(update_fields=["rating"])
        self.user2.stats.rating = 1500
        self.user2.stats.save(update_fields=["rating"])

        room = Room.objects.create(
            room_type="quick", host=self.user2, status="waiting", is_private=False
        )
        Room.objects.filter(pk=room.pk).update(created_at=timezone.now() - timedelta(seconds=90))

        matched_room, _, status = MatchmakingService.quick_match(self.user1)
        self.assertEqual(status, "matched")
        self.assertEqual(matched_room.host_id, self.user2.id)

    def test_recent_room_does_not_match_outside_base_band(self):
        self.user1.stats.rating = 1200
        self.user1.stats.save(update_fields=["rating"])
        self.user2.stats.rating = 1500
        self.user2.stats.save(update_fields=["rating"])

        existing = Room.objects.create(
            room_type="quick", host=self.user2, status="waiting", is_private=False
        )
        room, _, status = MatchmakingService.quick_match(self.user1)
        self.assertEqual(status, "waiting")
        self.assertNotEqual(room.id, existing.id)
        self.assertEqual(room.host_id, self.user1.id)

    def test_15_second_tier_expands_to_175(self):
        """15초 대기 시 175점 차이까지 매칭"""
        self.user1.stats.rating = 1200
        self.user1.stats.save(update_fields=["rating"])
        self.user2.stats.rating = 1370  # 170점 차이 (175 이내)
        self.user2.stats.save(update_fields=["rating"])

        room = Room.objects.create(
            room_type="quick", host=self.user2, status="waiting", is_private=False
        )
        Room.objects.filter(pk=room.pk).update(created_at=timezone.now() - timedelta(seconds=15))

        matched_room, _, status = MatchmakingService.quick_match(self.user1)
        self.assertEqual(status, "matched")
        self.assertEqual(matched_room.host_id, self.user2.id)

    def test_15_second_tier_does_not_match_outside_band(self):
        """15초 대기 시 175점 초과 차이는 매칭 안됨"""
        self.user1.stats.rating = 1200
        self.user1.stats.save(update_fields=["rating"])
        self.user2.stats.rating = 1400  # 200점 차이 (175 초과)
        self.user2.stats.save(update_fields=["rating"])

        room = Room.objects.create(
            room_type="quick", host=self.user2, status="waiting", is_private=False
        )
        Room.objects.filter(pk=room.pk).update(created_at=timezone.now() - timedelta(seconds=15))

        matched_room, _, status = MatchmakingService.quick_match(self.user1)
        self.assertEqual(status, "waiting")
        self.assertNotEqual(matched_room.id, room.id)

    def test_45_second_tier_expands_to_350(self):
        """45초 대기 시 350점 차이까지 매칭"""
        self.user1.stats.rating = 1200
        self.user1.stats.save(update_fields=["rating"])
        self.user2.stats.rating = 1540  # 340점 차이 (350 이내)
        self.user2.stats.save(update_fields=["rating"])

        room = Room.objects.create(
            room_type="quick", host=self.user2, status="waiting", is_private=False
        )
        Room.objects.filter(pk=room.pk).update(created_at=timezone.now() - timedelta(seconds=45))

        matched_room, _, status = MatchmakingService.quick_match(self.user1)
        self.assertEqual(status, "matched")
        self.assertEqual(matched_room.host_id, self.user2.id)

    def test_180_second_tier_expands_to_1000(self):
        """180초 대기 시 1000점 차이까지 매칭"""
        self.user1.stats.rating = 1200
        self.user1.stats.save(update_fields=["rating"])
        self.user2.stats.rating = 2100  # 900점 차이 (1000 이내)
        self.user2.stats.save(update_fields=["rating"])

        room = Room.objects.create(
            room_type="quick", host=self.user2, status="waiting", is_private=False
        )
        Room.objects.filter(pk=room.pk).update(created_at=timezone.now() - timedelta(seconds=180))

        matched_room, _, status = MatchmakingService.quick_match(self.user1)
        self.assertEqual(status, "matched")
        self.assertEqual(matched_room.host_id, self.user2.id)

    def test_allowed_rating_diff_returns_correct_tier(self):
        """_allowed_rating_diff 메서드 직접 테스트"""
        self.assertEqual(MatchmakingService._allowed_rating_diff(0), 125)
        self.assertEqual(MatchmakingService._allowed_rating_diff(14), 125)
        self.assertEqual(MatchmakingService._allowed_rating_diff(15), 175)
        self.assertEqual(MatchmakingService._allowed_rating_diff(29), 175)
        self.assertEqual(MatchmakingService._allowed_rating_diff(30), 250)
        self.assertEqual(MatchmakingService._allowed_rating_diff(45), 350)
        self.assertEqual(MatchmakingService._allowed_rating_diff(60), 500)
        self.assertEqual(MatchmakingService._allowed_rating_diff(90), 650)
        self.assertEqual(MatchmakingService._allowed_rating_diff(120), 800)
        self.assertEqual(MatchmakingService._allowed_rating_diff(180), 1000)
        self.assertEqual(MatchmakingService._allowed_rating_diff(300), 1200)
        self.assertEqual(MatchmakingService._allowed_rating_diff(600), 1200)  # 최대값 유지
