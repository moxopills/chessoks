from django.contrib.auth import get_user_model
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.chess.models import Game, Move, Room

User = get_user_model()


class GameApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.white = User.objects.create_user(
            email="apiwhite@test.com", nickname="화이트", password="Pass123!"
        )
        self.black = User.objects.create_user(
            email="apiblack@test.com", nickname="블랙", password="Pass123!"
        )
        self.other = User.objects.create_user(
            email="apiother@test.com", nickname="다른", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.white, guest=self.black, allow_spectators=False)
        self.game = Game.objects.create(
            room=self.room, white_player=self.white, black_player=self.black
        )

    def _create_move(self, move_number, player_color, san, uci, from_sq, to_sq):
        return Move.objects.create(
            game=self.game,
            move_number=move_number,
            player_color=player_color,
            piece="P",
            from_square=from_sq,
            to_square=to_sq,
            san=san,
            uci=uci,
            is_capture=False,
            is_check=False,
            is_checkmate=False,
            is_castling=False,
            is_en_passant=False,
            promotion="",
            fen_after_move=self.game.fen,
            time_spent=1.2,
        )

    def test_game_detail_success(self):
        self.client.force_authenticate(user=self.white)
        response = self.client.get(f"/api/chess/games/{self.game.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], self.game.id)
        self.assertEqual(response.data["white_player"]["id"], self.white.id)

    def test_game_detail_access_denied(self):
        self.client.force_authenticate(user=self.other)
        response = self.client.get(f"/api/chess/games/{self.game.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_game_moves_pagination(self):
        self._create_move(1, "white", "e4", "e2e4", "e2", "e4")
        self._create_move(1, "black", "e5", "e7e5", "e7", "e5")
        self._create_move(2, "white", "Nf3", "g1f3", "g1", "f3")

        self.client.force_authenticate(user=self.white)
        response = self.client.get(f"/api/chess/games/{self.game.id}/moves/?limit=2&offset=1")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 3)
        self.assertEqual(len(response.data["results"]), 2)
