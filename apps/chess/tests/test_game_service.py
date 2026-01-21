from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

import chess
from apps.chess.models import Game, Room
from apps.chess.services import GameService
from apps.chess.tasks import handle_timeouts

User = get_user_model()


class GameServiceTestCase(TestCase):
    def setUp(self):
        self.white = User.objects.create_user(
            email="white@test.com", nickname="화이트", password="Pass123!"
        )
        self.black = User.objects.create_user(
            email="black@test.com", nickname="블랙", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.white, guest=self.black, time_limit=15)
        self.room.status = "playing"
        self.room.save(update_fields=["status"])
        self.game = Game.objects.create(
            room=self.room, white_player=self.white, black_player=self.black
        )

    def test_make_move_updates_state_and_time(self):
        now = timezone.now()
        self.game.turn_started_at = now - timedelta(seconds=30)
        self.game.save(update_fields=["turn_started_at"])

        with patch("apps.chess.services.game_service.timezone") as mock_tz:
            mock_tz.now.return_value = now
            result = GameService.make_move(self.game.id, self.white, "e2e4")

        self.game.refresh_from_db()
        self.assertIsNotNone(result.move)
        self.assertEqual(self.game.current_turn, "black")
        self.assertEqual(self.game.move_count, 1)
        self.assertTrue(self.game.pgn.startswith("1."))
        self.assertEqual(self.game.white_time_remaining, (15 * 60) - 30 + 10)

    def test_make_move_rejects_wrong_turn(self):
        with self.assertRaises(ValidationError):
            GameService.make_move(self.game.id, self.black, "e7e5")

    def test_make_move_rejects_illegal_move(self):
        with self.assertRaises(ValidationError):
            GameService.make_move(self.game.id, self.white, "e2e5")

    def test_promotion_move_sets_promotion(self):
        self.game.fen = "8/P7/8/8/8/8/8/k6K w - - 0 1"
        self.game.current_turn = "white"
        self.game.save(update_fields=["fen", "current_turn"])

        result = GameService.make_move(self.game.id, self.white, "a7a8", promotion="Q")
        self.assertEqual(result.move.promotion, "Q")

    def test_checkmate_result(self):
        GameService.make_move(self.game.id, self.white, "f2f3")
        GameService.make_move(self.game.id, self.black, "e7e5")
        GameService.make_move(self.game.id, self.white, "g2g4")
        result = GameService.make_move(self.game.id, self.black, "d8h4")

        self.assertEqual(result.game.result, "checkmate_black")

    def test_stalemate_result(self):
        board = chess.Board("7k/5Q2/6K1/8/8/8/8/8 w - - 0 1")
        stalemate_move = None
        for move in board.legal_moves:
            temp = board.copy()
            temp.push(move)
            if temp.is_stalemate():
                stalemate_move = move.uci()
                break

        self.assertIsNotNone(stalemate_move)
        self.game.fen = board.fen()
        self.game.current_turn = "white"
        self.game.save(update_fields=["fen", "current_turn"])

        result = GameService.make_move(self.game.id, self.white, stalemate_move)
        self.assertEqual(result.game.result, "stalemate")

    def test_insufficient_material_result(self):
        self.game.fen = "8/8/8/8/8/8/8/K6k w - - 0 1"
        self.game.current_turn = "white"
        self.game.save(update_fields=["fen", "current_turn"])

        result = GameService.make_move(self.game.id, self.white, "a1a2")
        self.assertEqual(result.game.result, "draw_insufficient")

    def test_fifty_move_rule_result(self):
        self.game.fen = "7k/8/8/8/8/8/8/K6R w - - 99 1"
        self.game.current_turn = "white"
        self.game.save(update_fields=["fen", "current_turn"])

        result = GameService.make_move(self.game.id, self.white, "a1a2")
        self.assertEqual(result.game.result, "draw_fifty_move")

    def test_resign_sets_result(self):
        game = GameService.resign(self.game.id, self.white)
        self.assertEqual(game.result, "resignation_white")

    def test_draw_offer_pending_then_accepted(self):
        cache.clear()
        game, status, _ = GameService.request_draw(self.game.id, self.white)
        self.assertIsNone(game)
        self.assertEqual(status, "pending")

        game, status, _ = GameService.request_draw(self.game.id, self.black)
        self.assertIsNotNone(game)
        self.assertEqual(status, "accepted")
        self.assertEqual(game.result, "draw_agreement")

    def test_rematch_offer_pending_then_accepted(self):
        cache.clear()
        self.game.result = "checkmate_black"
        self.game.save(update_fields=["result"])

        game, status, _ = GameService.request_rematch(self.game.id, self.white)
        self.assertIsNone(game)
        self.assertEqual(status, "pending")

        game, status, _ = GameService.request_rematch(self.game.id, self.black)
        self.assertIsNotNone(game)
        self.assertEqual(status, "accepted")
        self.assertNotEqual(game.id, self.game.id)
        self.assertEqual(game.white_player, self.black)
        self.assertEqual(game.black_player, self.white)


class TimeoutTaskTestCase(TestCase):
    def setUp(self):
        self.white = User.objects.create_user(
            email="white2@test.com", nickname="화이트2", password="Pass123!"
        )
        self.black = User.objects.create_user(
            email="black2@test.com", nickname="블랙2", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.white, guest=self.black, time_limit=15)
        self.room.status = "playing"
        self.room.save(update_fields=["status"])
        self.game = Game.objects.create(
            room=self.room, white_player=self.white, black_player=self.black
        )

    def test_handle_timeouts_marks_timeout(self):
        now = timezone.now()
        self.game.turn_started_at = now - timedelta(seconds=5)
        self.game.white_time_remaining = 1
        self.game.save(update_fields=["turn_started_at", "white_time_remaining"])

        with patch("apps.chess.tasks.timezone") as mock_tz:
            mock_tz.now.return_value = now
            updated = handle_timeouts()

        self.game.refresh_from_db()
        self.assertEqual(updated, 1)
        self.assertEqual(self.game.result, "timeout_white")
