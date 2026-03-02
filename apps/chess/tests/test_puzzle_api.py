from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APIClient

from apps.chess.models import DailyPuzzle, Puzzle, UserPuzzleAttempt

User = get_user_model()


@override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
)
class PuzzleApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="puzzle@test.com", nickname="퍼즐유저", password="Pass123!"
        )
        self.guest_user = User.objects.create_user(
            email="guest-puzzle@test.com",
            nickname="게스트퍼즐",
            password="Pass123!",
            is_guest=True,
        )
        self.puzzle = Puzzle.objects.create(
            lichess_id="LCH001",
            fen="rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR b KQkq - 0 1",
            moves=["e7e5", "g1f3", "d7d6", "d2d4"],
            rating=1450,
            themes=["opening", "development"],
        )
        self.easy_puzzle = Puzzle.objects.create(
            lichess_id="LCH002",
            fen="rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR b KQkq - 0 1",
            moves=["e7e5", "d2d4", "e5d4", "d1d4"],
            rating=1000,
            themes=["opening"],
        )
        today = timezone.localdate()
        DailyPuzzle.objects.filter(date=today).delete()
        self.daily = DailyPuzzle.objects.create(date=today, level="medium", puzzle=self.puzzle)
        self.easy_daily = DailyPuzzle.objects.create(
            date=today, level="easy", puzzle=self.easy_puzzle
        )

    def test_get_daily_puzzle_with_attempt(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/puzzle/daily/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["puzzle"]["id"], self.puzzle.id)
        self.assertEqual(response.data["puzzle"]["first_move"], "e7e5")
        self.assertIn("attempt", response.data)
        self.assertEqual(response.data["hint_limit"], 3)
        self.assertEqual(response.data["hints_used"], 0)
        self.assertEqual(response.data["remaining_hints"], 3)
        self.assertTrue(
            UserPuzzleAttempt.objects.filter(user=self.user, daily_puzzle=self.daily).exists()
        )

    def test_get_daily_puzzle_by_level(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/puzzle/daily/?level=easy")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["level"], "easy")
        self.assertEqual(response.data["puzzle"]["id"], self.easy_puzzle.id)
        self.assertTrue(
            UserPuzzleAttempt.objects.filter(user=self.user, daily_puzzle=self.easy_daily).exists()
        )

    def test_get_daily_puzzle_invalid_level(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/puzzle/daily/?level=invalid")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_daily_puzzle_hard_fallback(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/puzzle/daily/?level=hard")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["level"], "hard")
        self.assertIsNotNone(response.data["puzzle"]["id"])

    def test_submit_move_correct_then_complete(self):
        self.client.force_authenticate(user=self.user)

        first = self.client.post("/api/chess/puzzle/daily/move/", {"move": "g1f3"}, format="json")
        self.assertEqual(first.status_code, status.HTTP_200_OK)
        self.assertTrue(first.data["correct"])
        self.assertFalse(first.data["completed"])
        self.assertEqual(first.data["next_move"], "d7d6")

        second = self.client.post("/api/chess/puzzle/daily/move/", {"move": "d2d4"}, format="json")
        self.assertEqual(second.status_code, status.HTTP_200_OK)
        self.assertTrue(second.data["correct"])
        self.assertTrue(second.data["completed"])

        attempt = UserPuzzleAttempt.objects.get(user=self.user, daily_puzzle=self.daily)
        self.assertTrue(attempt.solved)
        self.assertEqual(attempt.moves_made, ["g1f3", "d2d4"])

    def test_submit_move_wrong(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/chess/puzzle/daily/move/", {"move": "a2a3"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["correct"])
        attempt = UserPuzzleAttempt.objects.get(user=self.user, daily_puzzle=self.daily)
        self.assertFalse(attempt.solved)
        self.assertEqual(attempt.moves_made, [])
        self.assertEqual(attempt.attempts, 1)

    def test_submit_move_by_level(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/chess/puzzle/daily/move/",
            {"move": "d2d4", "level": "easy"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["correct"])

    def test_hint_and_solution(self):
        self.client.force_authenticate(user=self.user)
        hint = self.client.post("/api/chess/puzzle/daily/hint/")
        self.assertEqual(hint.status_code, status.HTTP_200_OK)
        self.assertEqual(hint.data["hint_type"], "piece")
        self.assertEqual(hint.data["square"], "g1")
        self.assertEqual(hint.data["hints_used"], 1)
        self.assertEqual(hint.data["remaining_hints"], 2)

        solution = self.client.get("/api/chess/puzzle/daily/solution/")
        self.assertEqual(solution.status_code, status.HTTP_200_OK)
        self.assertEqual(solution.data["moves"], self.puzzle.moves)

    def test_hint_limit_three_times(self):
        self.client.force_authenticate(user=self.user)
        self.client.post("/api/chess/puzzle/daily/hint/")
        self.client.post("/api/chess/puzzle/daily/hint/")
        self.client.post("/api/chess/puzzle/daily/hint/")
        fourth = self.client.post("/api/chess/puzzle/daily/hint/")
        self.assertEqual(fourth.status_code, status.HTTP_200_OK)
        self.assertEqual(fourth.data["hint_type"], "limit")
        self.assertEqual(fourth.data["remaining_hints"], 0)

    def test_guest_attempt_not_persisted_in_db(self):
        self.client.force_authenticate(user=self.guest_user)
        response = self.client.post(
            "/api/chess/puzzle/daily/move/", {"move": "g1f3"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["correct"])
        self.assertFalse(
            UserPuzzleAttempt.objects.filter(user=self.guest_user, daily_puzzle=self.daily).exists()
        )

    def test_stats_and_streak(self):
        self.client.force_authenticate(user=self.user)
        self.client.post("/api/chess/puzzle/daily/move/", {"move": "g1f3"}, format="json")
        self.client.post("/api/chess/puzzle/daily/move/", {"move": "d2d4"}, format="json")

        stats = self.client.get("/api/chess/puzzle/stats/")
        self.assertEqual(stats.status_code, status.HTTP_200_OK)
        self.assertEqual(stats.data["total"], 1)
        self.assertEqual(stats.data["solved"], 1)

        streak = self.client.get("/api/chess/puzzle/streak/")
        self.assertEqual(streak.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(streak.data["best_streak"], 1)
