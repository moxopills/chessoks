from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.tests.test_auth import User
from apps.chess.models import Room


class SpectatorFlowApiTestCase(TestCase):
    def setUp(self):
        self.host = User.objects.create_user(
            email="spec1@test.com", nickname="관전자1", password="Pass123!"
        )
        self.spectator = User.objects.create_user(
            email="spec2@test.com", nickname="관전자2", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.host, room_type="custom", allow_spectators=True)
        self.client = APIClient()
        self.client.login(email=self.spectator.email, password="Pass123!")

    def test_spectator_join_list_leave_flow(self):
        response = self.client.post(f"/api/chess/rooms/{self.room.id}/spectators/join/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.get(f"/api/chess/rooms/{self.room.id}/spectators/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["spectators"]), 1)

        response = self.client.post(f"/api/chess/rooms/{self.room.id}/spectators/leave/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
