from django.contrib.auth import get_user_model
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.chess.models import Room

User = get_user_model()


class RoomApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="room@test.com", nickname="방유저", password="Pass123!"
        )
        self.other = User.objects.create_user(
            email="room2@test.com", nickname="다른", password="Pass123!"
        )

        self.public_room = Room.objects.create(
            host=self.user,
            room_type="custom",
            status="waiting",
            is_private=False,
        )
        self.private_room = Room.objects.create(
            host=self.user,
            room_type="custom",
            status="waiting",
            is_private=True,
            password="hashed",
        )

    def test_room_list_excludes_private(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/rooms/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], self.public_room.id)

    def test_room_list_filters(self):
        Room.objects.create(
            host=self.other,
            room_type="quick",
            status="playing",
            is_private=False,
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/rooms/?room_type=quick&status=playing")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    def test_room_detail_public(self):
        self.client.force_authenticate(user=self.other)
        response = self.client.get(f"/api/chess/rooms/{self.public_room.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], self.public_room.id)

    def test_room_detail_private_denied(self):
        self.client.force_authenticate(user=self.other)
        response = self.client.get(f"/api/chess/rooms/{self.private_room.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_room_detail_private_allowed_for_host(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"/api/chess/rooms/{self.private_room.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], self.private_room.id)

    def test_room_detail_not_found(self):
        """존재하지 않는 방 조회 시 404"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/rooms/99999/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_room_list_excludes_finished_by_default(self):
        """기본 조회 시 종료된 방 제외"""
        Room.objects.create(
            host=self.other,
            room_type="custom",
            status="finished",
            is_private=False,
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/rooms/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)  # finished 제외

    def test_room_list_includes_finished_when_filtered(self):
        """status=finished 필터 시 종료된 방 조회 가능"""
        finished_room = Room.objects.create(
            host=self.other,
            room_type="custom",
            status="finished",
            is_private=False,
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/chess/rooms/?status=finished")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], finished_room.id)
