from django.core.cache import cache
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.services import OnlineStatusService
from apps.accounts.tests.test_auth import User


class OnlineStatusApiTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.user1 = User.objects.create_user(
            email="online1@test.com", nickname="온라인1", password="Pass123!"
        )
        self.user2 = User.objects.create_user(
            email="online2@test.com", nickname="온라인2", password="Pass123!"
        )

    def tearDown(self):
        cache.clear()

    def test_online_status_list(self):
        OnlineStatusService.set_online(self.user1.id)

        self.client.force_authenticate(user=self.user1)
        response = self.client.get(
            f"/api/accounts/online-status/?ids={self.user1.id},{self.user2.id}"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = {item["id"]: item["online"] for item in response.data["results"]}
        self.assertTrue(results[self.user1.id])
        self.assertFalse(results[self.user2.id])

    def test_online_status_empty_ids(self):
        """빈 ids 파라미터"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get("/api/accounts/online-status/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["results"], [])

    def test_online_status_invalid_ids(self):
        """잘못된 ids 파라미터 (무시됨)"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get("/api/accounts/online-status/?ids=abc,123,def")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["id"], 123)

    def test_heartbeat_refresh(self):
        """heartbeat가 TTL을 갱신하는지 확인"""
        OnlineStatusService.set_online(self.user1.id)
        self.assertTrue(OnlineStatusService.is_online(self.user1.id))

        OnlineStatusService.refresh(self.user1.id)
        self.assertTrue(OnlineStatusService.is_online(self.user1.id))

    def test_set_offline_removes_status(self):
        """명시적 오프라인 처리"""
        OnlineStatusService.set_online(self.user1.id)
        self.assertTrue(OnlineStatusService.is_online(self.user1.id))

        OnlineStatusService.set_offline(self.user1.id)
        self.assertFalse(OnlineStatusService.is_online(self.user1.id))
