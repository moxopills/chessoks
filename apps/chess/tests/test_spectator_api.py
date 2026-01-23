from django.contrib.auth import get_user_model
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.chess.models import Room

User = get_user_model()


class SpectatorApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.host = User.objects.create_user(
            email="host2@test.com", nickname="호스트2", password="Pass123!"
        )
        self.guest = User.objects.create_user(
            email="guest2@test.com", nickname="게스트2", password="Pass123!"
        )
        self.viewer = User.objects.create_user(
            email="viewer@test.com", nickname="관전자", password="Pass123!"
        )
        self.room = Room.objects.create(
            host=self.host,
            guest=self.guest,
            allow_spectators=True,
            is_private=False,
        )

    def test_join_and_leave_spectator(self):
        self.client.force_authenticate(user=self.viewer)

        response = self.client.post(f"/api/chess/rooms/{self.room.id}/spectators/join/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["spectators"]), 1)

        response = self.client.post(f"/api/chess/rooms/{self.room.id}/spectators/leave/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["spectators"]), 0)

    def test_list_spectators(self):
        self.client.force_authenticate(user=self.viewer)
        self.client.post(f"/api/chess/rooms/{self.room.id}/spectators/join/")

        response = self.client.get(f"/api/chess/rooms/{self.room.id}/spectators/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["spectators"]), 1)

    def test_player_cannot_join_as_spectator(self):
        """플레이어는 관전자로 참여 불가"""
        self.client.force_authenticate(user=self.host)
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/spectators/join/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_join_spectator_disabled_room(self):
        """관전 비허용 방 접근 불가"""
        no_spectator_room = Room.objects.create(
            host=self.host, guest=self.guest, allow_spectators=False
        )
        self.client.force_authenticate(user=self.viewer)
        response = self.client.post(f"/api/chess/rooms/{no_spectator_room.id}/spectators/join/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_join_room_not_found(self):
        """존재하지 않는 방"""
        self.client.force_authenticate(user=self.viewer)
        response = self.client.post("/api/chess/rooms/99999/spectators/join/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_list_spectators_private_room_non_player(self):
        """비공개 방 관전자 목록 - 비참가자 접근 불가"""
        private_room = Room.objects.create(
            host=self.host, guest=self.guest, allow_spectators=True, is_private=True
        )
        self.client.force_authenticate(user=self.viewer)
        response = self.client.get(f"/api/chess/rooms/{private_room.id}/spectators/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
