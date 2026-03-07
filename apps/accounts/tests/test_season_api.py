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

    def test_finalize_season_auto_grants_rewards(self):
        start = timezone.localdate() - timedelta(days=32)
        end = timezone.localdate() - timedelta(days=1)
        season = Season.objects.create(
            name="2026년 03월 시즌",
            start_date=start,
            end_date=end,
            is_active=True,
            is_finalized=False,
        )
        SeasonService._ensure_default_rewards(season)

        users = [self.user_a, self.user_b, self.user_c]
        for idx in range(4, 13):
            users.append(
                self.create_verified_user(email=f"s{idx}@test.com", nickname=f"시즌유저{idx}")
            )

        rating = 2100
        for user in users:
            SeasonStat.objects.create(
                season=season,
                user=user,
                rating=rating,
                peak_rating=rating,
                games_played=20,
                wins=12,
                losses=6,
                draws=2,
            )
            rating -= 10

        finalized_count = SeasonService.finalize_season(season)
        self.assertEqual(finalized_count, len(users))

        season.refresh_from_db()
        self.assertTrue(season.is_finalized)
        self.assertFalse(season.is_active)

        # 1위 보상
        stats_1 = self.user_a.stats
        stats_1.refresh_from_db()
        self.assertEqual(stats_1.style_points, 5000)
        self.assertIn("2026년 03월 시즌 1위", stats_1.owned_season_titles)
        self.assertEqual(stats_1.season_title, "2026년 03월 시즌 1위")
        self.assertIn("season_champion_frame", stats_1.owned_profile_card_frames)
        self.assertEqual(stats_1.profile_card_frame, "season_champion_frame")

        # 2위 보상
        stats_2 = self.user_b.stats
        stats_2.refresh_from_db()
        self.assertEqual(stats_2.style_points, 3000)
        self.assertIn("2026년 03월 시즌 2위", stats_2.owned_season_titles)
        self.assertIn("season_runnerup_frame", stats_2.owned_profile_card_frames)

        # 3위 보상
        stats_3 = self.user_c.stats
        stats_3.refresh_from_db()
        self.assertEqual(stats_3.style_points, 2000)
        self.assertIn("2026년 03월 시즌 3위", stats_3.owned_season_titles)
        self.assertIn("season_third_frame", stats_3.owned_profile_card_frames)

        # 4~10위 (TOP10 공통)
        stats_4 = users[3].stats
        stats_4.refresh_from_db()
        self.assertEqual(stats_4.style_points, 1200)
        self.assertIn("2026년 03월 시즌 TOP 10", stats_4.owned_season_titles)
        self.assertIn("season_top10_frame", stats_4.owned_profile_card_frames)

        # 11~30위 포인트 지급
        stats_11 = users[10].stats
        stats_11.refresh_from_db()
        self.assertEqual(stats_11.style_points, 700)

        claims = UserSeasonReward.objects.filter(season=season)
        self.assertTrue(claims.exists())
        self.assertFalse(claims.filter(claimed_at__isnull=True).exists())

    def test_claim_rewards_returns_zero_when_already_auto_claimed(self):
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
        UserSeasonReward.objects.create(
            user=self.user_a,
            season=season,
            reward=reward,
            claimed_at=timezone.now(),
        )
        self.client.force_authenticate(user=self.user_a)

        response = self.client.post(f"/api/seasons/{season.id}/rewards/claim/", {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["claimed_count"], 0)
