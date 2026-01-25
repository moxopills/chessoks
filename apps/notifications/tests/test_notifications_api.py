from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.tests.test_auth import User
from apps.notifications.models import Notification


class NotificationApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="notify@test.com", nickname="알림", password="Pass123!"
        )
        Notification.objects.create(
            user=self.user,
            type="game_result",
            title="게임 종료",
            message="승리했습니다.",
            payload={"game_id": 1},
        )

    def test_notification_list(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/notifications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    def test_notification_mark_read(self):
        self.client.force_authenticate(user=self.user)
        notif_id = Notification.objects.filter(user=self.user).first().id
        response = self.client.post(
            "/api/notifications/read/", {"ids": [notif_id]}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["updated"], 1)
        self.assertTrue(Notification.objects.get(id=notif_id).is_read)

    def test_notification_unread_count(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/notifications/unread/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

        Notification.objects.filter(user=self.user).update(is_read=True)
        response = self.client.get("/api/notifications/unread/")
        self.assertEqual(response.data["count"], 0)

    def test_mark_read_empty_ids(self):
        """빈 ids로 읽음 처리 시도"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post("/api/notifications/read/", {"ids": []}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_mark_read_already_read(self):
        """이미 읽은 알림 다시 읽음 처리"""
        notif = Notification.objects.filter(user=self.user).first()
        notif.is_read = True
        notif.save()

        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/notifications/read/", {"ids": [notif.id]}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["updated"], 0)

    def test_mark_read_other_user_notification(self):
        """타 유저 알림 읽음 처리 시도 (보안)"""
        other_user = User.objects.create_user(
            email="other@test.com", nickname="타유저", password="Pass123!"
        )
        other_notif = Notification.objects.create(
            user=other_user,
            type="game_result",
            title="타유저 알림",
            message="타유저 메시지",
        )

        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/notifications/read/", {"ids": [other_notif.id]}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["updated"], 0)
        self.assertFalse(Notification.objects.get(id=other_notif.id).is_read)

    def test_notification_list_pagination(self):
        """페이지네이션 테스트"""
        for i in range(5):
            Notification.objects.create(
                user=self.user,
                type="game_result",
                title=f"알림 {i}",
                message=f"메시지 {i}",
            )

        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/notifications/?limit=3&offset=0")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 6)
        self.assertEqual(len(response.data["results"]), 3)

        response = self.client.get("/api/notifications/?limit=3&offset=3")
        self.assertEqual(len(response.data["results"]), 3)
