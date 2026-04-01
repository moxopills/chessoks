from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.models import SignupEmailToken
from apps.accounts.services.token_service import TokenService
from apps.accounts.tests.test_auth import User
from apps.accounts.utils import hash_signup_code_for_test
from apps.notifications.models import Notification


class AccountAndSocialFlowsTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_account_flow_signup_profile_logout(self):
        SignupEmailToken.objects.create(
            email="flow@test.com",
            token=TokenService.generate_token(),
            code_hash=hash_signup_code_for_test("flow@test.com", "123456"),
            expires_at=timezone.now() + timedelta(hours=24),
        )
        from django.core.cache import cache

        cache.set("signup_email_verified:flow@test.com", True, timeout=600)
        response = self.client.post(
            "/api/accounts/signup/",
            {
                "email": "flow@test.com",
                "nickname": "플로우",
                "bio": "소개",
                "password": "Pass123!",
                "password2": "Pass123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        self.assertTrue(self.client.login(email="flow@test.com", password="Pass123!"))

        response = self.client.get("/api/accounts/me/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.patch("/api/accounts/profile/", {"bio": "수정"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.post("/api/accounts/logout/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class FriendNotificationLeaderboardFlowTestCase(TestCase):
    def setUp(self):
        self.user_a = User.objects.create_user(
            email="fa@test.com", nickname="친구A", password="Pass123!"
        )
        self.user_b = User.objects.create_user(
            email="fb@test.com", nickname="친구B", password="Pass123!"
        )
        self.client_a = APIClient()
        self.client_b = APIClient()
        self.client_a.login(email=self.user_a.email, password="Pass123!")
        self.client_b.login(email=self.user_b.email, password="Pass123!")

    def test_friend_request_accept_notification(self):
        response = self.client_a.post(
            "/api/accounts/friends/requests/", {"user_id": self.user_b.id}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client_b.get("/api/notifications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

        notif_id = Notification.objects.filter(user=self.user_b).first().id
        response = self.client_b.post(
            "/api/notifications/read/", {"ids": [notif_id]}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client_b.get("/api/accounts/friends/requests/?type=incoming")
        request_id = response.data["results"][0]["id"]
        response = self.client_b.post(f"/api/accounts/friends/requests/{request_id}/accept/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client_a.get("/api/accounts/friends/")
        self.assertEqual(response.data["count"], 1)

    def test_leaderboard_profile_dashboard(self):
        response = self.client_a.get("/api/accounts/leaderboard/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client_a.get(f"/api/accounts/users/{self.user_b.id}/profile/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client_a.get("/api/accounts/dashboard/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
