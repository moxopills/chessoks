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
        self.assertEqual(response.data["count"], 2)

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
        self.assertEqual(response.data["count"], 2)  # finished 제외, private 포함

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


class RoomCreateApiTestCase(TestCase):
    """방 생성 API 테스트"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="creator@test.com", nickname="생성자", password="Pass123!"
        )

    def test_create_room_basic(self):
        """기본 방 생성"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/chess/rooms/",
            {
                "room_type": "custom",
                "title": "테스트 방",
                "time_limit": 10,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["title"], "테스트 방")
        self.assertEqual(response.data["time_limit"], 10)
        self.assertEqual(response.data["host"]["id"], self.user.id)
        self.assertFalse(response.data["is_private"])

    def test_create_room_with_password(self):
        """비밀번호 있는 비공개 방 생성"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/chess/rooms/",
            {
                "room_type": "custom",
                "title": "비공개 방",
                "password": "secret123",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["is_private"])

        # DB에서 확인
        room = Room.objects.get(pk=response.data["id"])
        self.assertTrue(room.check_password("secret123"))

    def test_create_room_default_values(self):
        """기본값으로 방 생성"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post("/api/chess/rooms/", {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["room_type"], "custom")
        self.assertEqual(response.data["time_limit"], 15)
        self.assertTrue(response.data["allow_spectators"])

    def test_create_room_spectator_disabled(self):
        """관전 비허용 방 생성"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/chess/rooms/",
            {
                "allow_spectators": False,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertFalse(response.data["allow_spectators"])

    def test_create_room_unauthenticated(self):
        """비로그인 시 방 생성 불가"""
        response = self.client.post(
            "/api/chess/rooms/",
            {
                "title": "테스트",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_room_invalid_time_limit(self):
        """잘못된 시간 제한"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/chess/rooms/",
            {
                "time_limit": 0,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.post(
            "/api/chess/rooms/",
            {
                "time_limit": 100,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_room_invalid_room_type(self):
        """잘못된 방 타입"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            "/api/chess/rooms/",
            {
                "room_type": "invalid",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
