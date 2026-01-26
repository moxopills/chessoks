from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.tests.test_auth import User
from apps.chess.models import Game, Room


class OpponentProfileApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="viewer@test.com", nickname="뷰어", password="Pass123!"
        )
        self.opponent = User.objects.create_user(
            email="opponent@test.com", nickname="상대", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.user, guest=self.opponent, status="playing")

        game1 = Game.objects.create(
            room=self.room, white_player=self.user, black_player=self.opponent
        )
        game1.result = "checkmate_white"
        game1.save(update_fields=["result"])

        game2 = Game.objects.create(
            room=self.room, white_player=self.user, black_player=self.opponent
        )
        game2.result = "draw_agreement"
        game2.save(update_fields=["result"])

        game3 = Game.objects.create(
            room=self.room, white_player=self.opponent, black_player=self.user
        )
        game3.result = "resignation_white"
        game3.save(update_fields=["result"])

    def test_opponent_profile_with_summary(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"/api/accounts/users/{self.opponent.id}/profile/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user"]["id"], self.opponent.id)
        self.assertEqual(response.data["vs_summary"]["total"], 3)
        self.assertEqual(response.data["vs_summary"]["wins"], 2)
        self.assertEqual(response.data["vs_summary"]["losses"], 0)
        self.assertEqual(response.data["vs_summary"]["draws"], 1)

    def test_opponent_profile_anonymous(self):
        response = self.client.get(f"/api/accounts/users/{self.opponent.id}/profile/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["vs_summary"])

    def test_opponent_profile_not_found(self):
        """존재하지 않는 유저 프로필 조회"""
        response = self.client.get("/api/accounts/users/99999/profile/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
