from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APIClient

from apps.chess.models import Game, Room

User = get_user_model()


class GameHistoryApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="history@test.com", nickname="히스토리", password="Pass123!"
        )
        self.opponent = User.objects.create_user(
            email="opp@test.com", nickname="상대", password="Pass123!"
        )

        self.quick_room = Room.objects.create(
            host=self.user, guest=self.opponent, room_type="quick"
        )
        self.custom_room = Room.objects.create(
            host=self.user, guest=self.opponent, room_type="custom"
        )

        self.game_quick = Game.objects.create(
            room=self.quick_room,
            white_player=self.user,
            black_player=self.opponent,
            result="checkmate_white",
        )
        Game.objects.filter(pk=self.game_quick.pk).update(
            created_at=timezone.now() - timedelta(days=2)
        )

        self.game_custom = Game.objects.create(
            room=self.custom_room,
            white_player=self.opponent,
            black_player=self.user,
            result="draw_agreement",
        )
        Game.objects.filter(pk=self.game_custom.pk).update(
            created_at=timezone.now() - timedelta(days=1)
        )

    def test_history_filter_by_room_type(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/games/history/?room_type=quick")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["room_type"], "quick")

    def test_history_filter_by_result(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/games/history/?result=draw_agreement")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["result"], "draw_agreement")

    def test_history_filter_by_opponent(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"/api/chess/games/history/?opponent={self.opponent.nickname}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)

    def test_history_filter_by_date_range(self):
        self.client.force_authenticate(user=self.user)
        start = (timezone.now() - timedelta(days=1)).date().isoformat()
        end = timezone.now().date().isoformat()
        response = self.client.get(f"/api/chess/games/history/?start_date={start}&end_date={end}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    def test_history_excludes_playing_games(self):
        """진행 중인 게임은 기본 조회에서 제외"""
        playing_room = Room.objects.create(host=self.user, guest=self.opponent, room_type="quick")
        Game.objects.create(
            room=playing_room,
            white_player=self.user,
            black_player=self.opponent,
            result="playing",
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/games/history/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)  # playing 제외, 완료된 게임만

    def test_history_includes_playing_when_filtered(self):
        """result=playing 필터 시 진행 중인 게임 조회 가능"""
        playing_room = Room.objects.create(host=self.user, guest=self.opponent, room_type="quick")
        Game.objects.create(
            room=playing_room,
            white_player=self.user,
            black_player=self.opponent,
            result="playing",
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/games/history/?result=playing")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["result"], "playing")
