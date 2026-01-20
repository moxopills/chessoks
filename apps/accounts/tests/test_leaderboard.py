from rest_framework import status

from apps.accounts.tests.test_auth import BaseAPITestCase


class LeaderboardAPITestCase(BaseAPITestCase):
    def setUp(self):
        self.user_a = self.create_user(email="a@example.com", nickname="A")
        self.user_b = self.create_user(email="b@example.com", nickname="B")
        self.user_c = self.create_user(email="c@example.com", nickname="C")

        self.user_a.stats.rating = 1500
        self.user_a.stats.games_played = 20
        self.user_a.stats.save(update_fields=["rating", "games_played"])

        self.user_b.stats.rating = 1500
        self.user_b.stats.games_played = 10
        self.user_b.stats.save(update_fields=["rating", "games_played"])

        self.user_c.stats.rating = 1400
        self.user_c.stats.games_played = 30
        self.user_c.stats.save(update_fields=["rating", "games_played"])

    def test_leaderboard_ordering(self):
        """랭킹 보드 정렬 순서 테스트 (rating > games_played > id)"""
        response = self.client.get("/api/accounts/leaderboard/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 페이지네이션 응답 구조 확인
        self.assertIn("count", response.data)
        self.assertIn("results", response.data)
        self.assertEqual(response.data["count"], 3)

        results = response.data["results"]
        self.assertEqual(results[0]["nickname"], "A")
        self.assertEqual(results[0]["rank"], 1)
        self.assertEqual(results[1]["nickname"], "B")
        self.assertEqual(results[1]["rank"], 2)
        self.assertEqual(results[2]["nickname"], "C")
        self.assertEqual(results[2]["rank"], 3)

    def test_leaderboard_with_my_rank(self):
        """로그인 시 내 랭킹 포함 테스트"""
        self.client.force_authenticate(user=self.user_b)
        response = self.client.get("/api/accounts/leaderboard/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # my_rank 포함 확인
        self.assertIn("my_rank", response.data)
        self.assertEqual(response.data["my_rank"]["nickname"], "B")
        self.assertEqual(response.data["my_rank"]["rank"], 2)

    def test_leaderboard_pagination(self):
        """페이지네이션 테스트"""
        response = self.client.get("/api/accounts/leaderboard/?page_size=2")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 2)
        self.assertEqual(response.data["total_pages"], 2)
        self.assertEqual(response.data["current_page"], 1)

    def test_my_rank(self):
        """내 랭킹 조회 테스트"""
        self.client.force_authenticate(user=self.user_b)
        response = self.client.get("/api/accounts/leaderboard/me/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["nickname"], "B")
        self.assertEqual(response.data["rank"], 2)
