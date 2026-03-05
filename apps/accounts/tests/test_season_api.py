from datetime import timedelta

from django.utils import timezone

from rest_framework import status

from apps.accounts.models import Season, SeasonReward, SeasonStat, UserSeasonReward
from apps.accounts.services import SeasonService
from apps.accounts.tests.test_auth import BaseAPITestCase


class SeasonApiTestCase(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.user_a = self.create_verified_user(email="sa@test.com", nickname="시즌A")
        self.user_b = self.create_verified_user(email="sb@test.com", nickname="시즌B")
        self.user_c = self.create_verified_user(email="sc@test.com", nickname="시즌C")

    def test_current_season_auto_create(self):
        response = self.client.get("/api/seasons/current/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("id", response.data)
        self.assertEqual(Season.objects.filter(is_active=True).count(), 1)

    def test_current_leaderboard_filters_min_games(self):
        season = SeasonService.get_or_create_current_season()
        SeasonStat.objects.create(
            season=season, user=self.user_a, rating=1400, games_played=12, wins=8
        )
        SeasonStat.objects.create(
            season=season, user=self.user_b, rating=1500, games_played=9, wins=7
        )
        SeasonStat.objects.create(
            season=season, user=self.user_c, rating=1300, games_played=11, wins=6
        )

        response = self.client.get("/api/seasons/current/leaderboard/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)
        nicknames = [item["nickname"] for item in response.data["results"]]
        self.assertEqual(nicknames, ["시즌A", "시즌C"])

    def test_current_leaderboard_no_count_mode(self):
        season = SeasonService.get_or_create_current_season()
        for idx in range(25):
            user = self.create_verified_user(email=f"rank{idx}@test.com", nickname=f"랭커{idx}")
            SeasonStat.objects.create(
                season=season,
                user=user,
                rating=1500 - idx,
                games_played=15,
                wins=8,
                losses=7,
            )

        response = self.client.get(
            "/api/seasons/current/leaderboard/?page=1&page_size=20&no_count=true"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["count"])
        self.assertIsNone(response.data["total_pages"])
        self.assertTrue(response.data["has_next"])
        self.assertEqual(len(response.data["results"]), 20)

    def test_current_me_rank(self):
        season = SeasonService.get_or_create_current_season()
        SeasonStat.objects.create(
            season=season, user=self.user_a, rating=1600, games_played=11, wins=7
        )
        SeasonStat.objects.create(
            season=season, user=self.user_b, rating=1700, games_played=12, wins=8
        )
        self.client.force_authenticate(user=self.user_a)

        response = self.client.get("/api/seasons/current/me/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["my_rank"]["rank"], 2)

    def test_claim_rewards(self):
        start = timezone.localdate() - timedelta(days=32)
        end = timezone.localdate() - timedelta(days=1)
        season = Season.objects.create(
            name="지난 시즌", start_date=start, end_date=end, is_active=False, is_finalized=True
        )
        reward = SeasonReward.objects.create(
            season=season,
            rank_min=1,
            rank_max=1,
            reward_type=SeasonReward.TYPE_POINTS,
            reward_value="300",
        )
        UserSeasonReward.objects.create(user=self.user_a, season=season, reward=reward)
        self.client.force_authenticate(user=self.user_a)
        before = self.user_a.stats.style_points

        response = self.client.post(f"/api/seasons/{season.id}/rewards/claim/", {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["claimed_count"], 1)

        self.user_a.stats.refresh_from_db()
        self.assertEqual(self.user_a.stats.style_points, before + 300)
        claim = UserSeasonReward.objects.get(user=self.user_a, reward=reward)
        self.assertIsNotNone(claim.claimed_at)
