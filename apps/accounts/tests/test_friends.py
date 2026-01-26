from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.tests.test_auth import BaseTestCase, User


class FriendApiTestCase(BaseTestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="user1@test.com", nickname="유저1", password="Pass123!"
        )
        self.other = User.objects.create_user(
            email="user2@test.com", nickname="유저2", password="Pass123!"
        )

    def test_send_and_accept_friend_request(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.other.id}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        self.client.force_authenticate(user=self.other)
        requests = self.client.get("/api/accounts/friends/requests/?type=incoming")
        self.assertEqual(requests.status_code, status.HTTP_200_OK)
        request_id = requests.data["results"][0]["id"]

        accept = self.client.post(f"/api/accounts/friends/requests/{request_id}/accept/")
        self.assertEqual(accept.status_code, status.HTTP_200_OK)

        friends = self.client.get("/api/accounts/friends/")
        self.assertEqual(friends.status_code, status.HTTP_200_OK)
        self.assertEqual(friends.data["count"], 1)

    def test_send_request_to_self_blocked(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.user.id}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_auto_accept_reverse_request(self):
        self.client.force_authenticate(user=self.user)
        self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.other.id}, format="json"
        )

        self.client.force_authenticate(user=self.other)
        response = self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.user.id}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "accepted")

        friends = self.client.get("/api/accounts/friends/")
        self.assertEqual(friends.data["count"], 1)

    def test_reject_friend_request(self):
        """친구 요청 거절"""
        self.client.force_authenticate(user=self.user)
        self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.other.id}, format="json"
        )

        self.client.force_authenticate(user=self.other)
        requests = self.client.get("/api/accounts/friends/requests/?type=incoming")
        request_id = requests.data["results"][0]["id"]

        response = self.client.post(f"/api/accounts/friends/requests/{request_id}/reject/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        friends = self.client.get("/api/accounts/friends/")
        self.assertEqual(friends.data["count"], 0)

    def test_duplicate_friend_request(self):
        """중복 친구 요청"""
        self.client.force_authenticate(user=self.user)
        self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.other.id}, format="json"
        )
        response = self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.other.id}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_request_already_friends(self):
        """이미 친구 상태에서 요청"""
        self.client.force_authenticate(user=self.user)
        self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.other.id}, format="json"
        )

        self.client.force_authenticate(user=self.other)
        requests = self.client.get("/api/accounts/friends/requests/?type=incoming")
        request_id = requests.data["results"][0]["id"]
        self.client.post(f"/api/accounts/friends/requests/{request_id}/accept/")

        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/accounts/friends/requests/", {"user_id": self.other.id}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_request_not_found(self):
        """존재하지 않는 요청 수락"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post("/api/accounts/friends/requests/99999/accept/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_request_user_not_found(self):
        """존재하지 않는 유저에게 요청"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/accounts/friends/requests/", {"user_id": 99999}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
