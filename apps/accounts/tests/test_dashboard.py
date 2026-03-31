from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.tests.test_auth import User
from apps.chess.models import Game, Room


class DashboardApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="dash@test.com", nickname="대시", password="Pass123!"
        )
        self.opponent = User.objects.create_user(
            email="dash2@test.com", nickname="대시2", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.user, guest=self.opponent, status="playing")

        game = Game.objects.create(
            room=self.room, white_player=self.user, black_player=self.opponent
        )
        game.result = "checkmate_white"
        game.save(update_fields=["result"])
        self.user.stats.games_played = 1
        self.user.stats.games_won = 1
        self.user.stats.save(update_fields=["games_played", "games_won"])

    def test_dashboard(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/accounts/dashboard/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("summary", response.data)
        self.assertIn("achievements", response.data)
        self.assertEqual(response.data["summary"]["games_played"], 1)
        self.assertTrue(any(item["key"] == "first_win" for item in response.data["achievements"]))

    def test_dashboard_unauthenticated(self):
        """인증 없이 대시보드 접근"""
        response = self.client.get("/api/accounts/dashboard/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
