from django.contrib.auth import get_user_model
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.chess.models import Room

User = get_user_model()


class RoomFlowApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.host = User.objects.create_user(
            email="host@test.com", nickname="호스트", password="Pass123!"
        )
        self.guest = User.objects.create_user(
            email="guest@test.com", nickname="게스트", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.host, guest=self.guest, room_type="custom")

    def test_ready_and_start_flow(self):
        self.client.force_authenticate(user=self.host)
        response = self.client.post(
            f"/api/chess/rooms/{self.room.id}/ready/", {"ready": True}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["guest_ready"])

        self.client.force_authenticate(user=self.guest)
        response = self.client.post(
            f"/api/chess/rooms/{self.room.id}/ready/", {"ready": True}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "ready")

        response = self.client.post(f"/api/chess/rooms/{self.room.id}/start/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["game_id"])

        self.client.force_authenticate(user=self.host)
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/start/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "playing")
        self.assertIsNotNone(response.data["game_id"])

    def test_ready_cancel_resets_confirm(self):
        self.client.force_authenticate(user=self.host)
        self.client.post(f"/api/chess/rooms/{self.room.id}/ready/", {"ready": True}, format="json")
        self.client.post(f"/api/chess/rooms/{self.room.id}/start/")

        response = self.client.post(
            f"/api/chess/rooms/{self.room.id}/ready/", {"ready": False}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "waiting")

    def test_ready_room_not_found(self):
        self.client.force_authenticate(user=self.host)
        response = self.client.post("/api/chess/rooms/99999/ready/", {"ready": True}, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_start_room_not_found(self):
        self.client.force_authenticate(user=self.host)
        response = self.client.post("/api/chess/rooms/99999/start/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_ready_non_player(self):
        outsider = User.objects.create_user(
            email="outsider@test.com", nickname="외부인", password="Pass123!"
        )
        self.client.force_authenticate(user=outsider)
        response = self.client.post(
            f"/api/chess/rooms/{self.room.id}/ready/", {"ready": True}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_start_without_both_ready(self):
        self.client.force_authenticate(user=self.host)
        self.client.post(f"/api/chess/rooms/{self.room.id}/ready/", {"ready": True}, format="json")
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/start/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_start_without_guest(self):
        room_no_guest = Room.objects.create(host=self.host, room_type="custom")
        self.client.force_authenticate(user=self.host)
        self.client.post(
            f"/api/chess/rooms/{room_no_guest.id}/ready/", {"ready": True}, format="json"
        )
        response = self.client.post(f"/api/chess/rooms/{room_no_guest.id}/start/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
