from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.tests.test_auth import User
from apps.chess.models import Room


class RoomJoinLeaveApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.host = User.objects.create_user(
            email="host@test.com", nickname="호스트", password="Pass123!"
        )
        self.guest = User.objects.create_user(
            email="guest@test.com", nickname="게스트", password="Pass123!"
        )
        self.other = User.objects.create_user(
            email="other@test.com", nickname="다른유저", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.host, room_type="custom")
        self.private_room = Room.objects.create(host=self.host, room_type="custom", is_private=True)
        self.private_room.set_password("secret123")
        self.private_room.save(update_fields=["password"])

    def test_join_public_room(self):
        self.client.force_authenticate(user=self.other)
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/join/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["guest"]["id"], self.other.id)

    def test_join_full_room_blocked(self):
        self.room.guest = self.guest
        self.room.save(update_fields=["guest"])
        self.client.force_authenticate(user=self.other)
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/join/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_join_private_room_password(self):
        self.client.force_authenticate(user=self.other)
        response = self.client.post(
            f"/api/chess/rooms/{self.private_room.id}/join/",
            {"password": "wrong"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.post(
            f"/api/chess/rooms/{self.private_room.id}/join/",
            {"password": "secret123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_leave_room_as_guest(self):
        self.room.guest = self.guest
        self.room.save(update_fields=["guest"])
        self.client.force_authenticate(user=self.guest)
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/leave/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["deleted"])
        self.room.refresh_from_db()
        self.assertIsNone(self.room.guest)
        self.assertEqual(self.room.status, "waiting")

    def test_leave_room_as_host_deletes_room(self):
        self.room.guest = self.guest
        self.room.save(update_fields=["guest"])
        self.client.force_authenticate(user=self.host)
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/leave/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["deleted"])
        self.assertFalse(Room.objects.filter(id=self.room.id).exists())

    def test_join_room_not_found(self):
        """존재하지 않는 방 입장"""
        self.client.force_authenticate(user=self.other)
        response = self.client.post("/api/chess/rooms/99999/join/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_leave_room_not_found(self):
        """존재하지 않는 방 퇴장"""
        self.client.force_authenticate(user=self.host)
        response = self.client.post("/api/chess/rooms/99999/leave/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_leave_room_during_game_blocked(self):
        """게임 중 방 퇴장 차단"""
        self.room.guest = self.guest
        self.room.status = "playing"
        self.room.save(update_fields=["guest", "status"])
        self.client.force_authenticate(user=self.guest)
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/leave/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_join_playing_room_blocked(self):
        """게임 중인 방 입장 차단"""
        self.room.guest = self.guest
        self.room.status = "playing"
        self.room.save(update_fields=["guest", "status"])
        self.client.force_authenticate(user=self.other)
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/join/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
