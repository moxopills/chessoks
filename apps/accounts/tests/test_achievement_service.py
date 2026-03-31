from django.test import TestCase

from apps.accounts.models.skin import SkinPointLog
from apps.accounts.services import AchievementService
from apps.accounts.tests.test_auth import User


class AchievementServiceTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="achieve@test.com",
            nickname="업적유저",
            password="Pass123!",
        )

    def test_sync_rewards_grants_points_once_and_sets_featured_achievement(self):
        stats = self.user.stats
        stats.games_played = 1
        stats.games_won = 1
        stats.save(update_fields=["games_played", "games_won"])

        rewards = AchievementService.sync_rewards_for_user(self.user.id)

        stats.refresh_from_db()
        self.assertEqual(len(rewards), 1)
        self.assertEqual(rewards[0]["key"], "first_win")
        self.assertEqual(rewards[0]["reward_points"], 5)
        self.assertEqual(stats.style_points, 5)
        self.assertEqual(stats.earned_achievement_keys, ["first_win"])
        self.assertEqual(stats.featured_achievement_key, "first_win")
        self.assertEqual(
            SkinPointLog.objects.filter(
                user_id=self.user.id,
                reason=SkinPointLog.Reason.ACHIEVEMENT_REWARD,
                reference_id="achievement:first_win",
            ).count(),
            1,
        )

        rewards = AchievementService.sync_rewards_for_user(self.user.id)

        stats.refresh_from_db()
        self.assertEqual(rewards, [])
        self.assertEqual(stats.style_points, 5)
        self.assertEqual(
            SkinPointLog.objects.filter(
                user_id=self.user.id,
                reason=SkinPointLog.Reason.ACHIEVEMENT_REWARD,
                reference_id="achievement:first_win",
            ).count(),
            1,
        )
