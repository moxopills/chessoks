from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from rest_framework.exceptions import ValidationError

from apps.chess.models import Game, Move, Room
from apps.chess.services.game_query_service import GameQueryService

User = get_user_model()


class GameQueryServiceTestCase(TestCase):
    def setUp(self):
        self.white = User.objects.create_user(
            email="white@test.com", nickname="화이트", password="Pass123!"
        )
        self.black = User.objects.create_user(
            email="black@test.com", nickname="블랙", password="Pass123!"
        )
        self.other = User.objects.create_user(
            email="other@test.com", nickname="다른", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.white, guest=self.black, allow_spectators=True)
        self.game = Game.objects.create(
            room=self.room, white_player=self.white, black_player=self.black
        )

    def _create_move(self, move_number, player_color, uci, is_capture=False, **kwargs):
        return Move.objects.create(
            game=self.game,
            move_number=move_number,
            player_color=player_color,
            piece=kwargs.get("piece", "P"),
            from_square=uci[:2],
            to_square=uci[2:4],
            san=kwargs.get("san", uci),
            uci=uci,
            is_capture=is_capture,
            is_check=False,
            is_checkmate=False,
            is_castling=False,
            is_en_passant=kwargs.get("is_en_passant", False),
            captured_piece=kwargs.get("captured_piece", ""),
            captured_color=kwargs.get("captured_color", ""),
            promotion="",
            fen_after_move=self.game.fen,
            time_spent=1.0,
        )

    def test_list_legal_moves_only_for_current_player(self):
        moves = GameQueryService.list_legal_moves(self.game.id, self.other, None)
        self.assertEqual(moves, [])

        self.game.current_turn = "black"
        self.game.save(update_fields=["current_turn"])
        moves = GameQueryService.list_legal_moves(self.game.id, self.white, None)
        self.assertEqual(moves, [])

    def test_list_legal_moves_invalid_from_square(self):
        with self.assertRaises(ValidationError):
            GameQueryService.list_legal_moves(self.game.id, self.white, "e2e4")

    def test_captured_summary_uses_new_fields(self):
        self._create_move(
            1,
            "white",
            "e2e4",
            is_capture=False,
        )
        self._create_move(
            1,
            "black",
            "d7d5",
            is_capture=False,
        )
        self._create_move(
            2,
            "white",
            "e4d5",
            is_capture=True,
            captured_piece="P",
            captured_color="black",
        )
        captured = GameQueryService.captured_summary(self.game.id, self.white)
        self.assertEqual(captured["black"], ["P"])
        self.assertEqual(captured["white"], [])

    def test_captured_summary_fallback_reconstructs_board(self):
        Move.objects.all().delete()
        self._create_move(1, "white", "e2e4", is_capture=False)
        self._create_move(1, "black", "d7d5", is_capture=False)
        self._create_move(2, "white", "e4d5", is_capture=True)
        captured = GameQueryService.captured_summary(self.game.id, self.white)
        self.assertEqual(captured["black"], ["P"])

    def test_list_history_no_count(self):
        room_quick = Room.objects.create(host=self.white, guest=self.black, room_type="quick")
        finished = Game.objects.create(
            room=room_quick,
            white_player=self.white,
            black_player=self.black,
            result="checkmate_white",
        )
        Game.objects.filter(pk=finished.pk).update(created_at=timezone.now() - timedelta(days=1))
        total, games = GameQueryService.list_history(
            self.white,
            opponent=None,
            start_date=None,
            end_date=None,
            result=None,
            room_type=None,
            limit=10,
            offset=0,
            no_count=True,
        )
        self.assertEqual(total, len(games))
        self.assertEqual(games[0].id, finished.id)
