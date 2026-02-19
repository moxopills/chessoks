"""게스트 세션 테스트"""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from rest_framework.test import APIClient

from apps.accounts.models import GuestSession, User


class GuestSessionModelTest(TestCase):
    """GuestSession 모델 테스트"""

    def test_create_guest_session(self):
        """게스트 세션 생성 테스트"""
        guest = GuestSession.objects.create(
            nickname="테스트유저",
            ip_address="127.0.0.1",
        )

        self.assertIsNotNone(guest.token)
        self.assertEqual(len(guest.token), 43)  # base64 encoded 32 bytes
        self.assertEqual(guest.display_name, "[게스트] 테스트유저")
        self.assertIsNotNone(guest.expires_at)
        self.assertFalse(guest.is_expired)

    def test_is_expired(self):
        """만료 확인 테스트"""
        guest = GuestSession.objects.create(
            nickname="만료테스트",
            expires_at=timezone.now() - timedelta(hours=1),
        )

        self.assertTrue(guest.is_expired)

    def test_cleanup_expired(self):
        """만료된 세션 정리 테스트"""
        # 만료된 세션 생성
        GuestSession.objects.create(
            nickname="만료1",
            expires_at=timezone.now() - timedelta(hours=1),
        )
        GuestSession.objects.create(
            nickname="만료2",
            expires_at=timezone.now() - timedelta(hours=2),
        )
        # 유효한 세션
        valid = GuestSession.objects.create(nickname="유효")

        deleted = GuestSession.cleanup_expired()

        self.assertEqual(deleted, 2)
        self.assertEqual(GuestSession.objects.count(), 1)
        self.assertEqual(GuestSession.objects.first().id, valid.id)


class GuestSessionAPITest(TestCase):
    """게스트 세션 API 테스트"""

    def setUp(self):
        self.client = APIClient()

    def test_create_guest_session(self):
        """게스트 세션 생성 API 테스트"""
        response = self.client.post(
            "/api/accounts/guest/",
            {"nickname": "테스트게스트"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertIn("token", response.data)
        self.assertIn("nickname", response.data)
        self.assertIn("display_name", response.data)
        self.assertEqual(response.data["display_name"], "[게스트] 테스트게스트")

    def test_create_guest_session_invalid_nickname(self):
        """잘못된 닉네임으로 게스트 세션 생성 실패 테스트"""
        # 너무 짧음
        response = self.client.post(
            "/api/accounts/guest/",
            {"nickname": "a"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        # 너무 김
        response = self.client.post(
            "/api/accounts/guest/",
            {"nickname": "a" * 20},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

        # 특수문자
        response = self.client.post(
            "/api/accounts/guest/",
            {"nickname": "test@user"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_create_guest_session_forbidden_nickname(self):
        """금칙어 닉네임으로 게스트 세션 생성 실패 테스트"""
        response = self.client.post(
            "/api/accounts/guest/",
            {"nickname": "admin"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_create_guest_session_duplicate_user_nickname(self):
        """기존 유저 닉네임과 중복 시 접미사 추가 테스트"""
        User.objects.create_user(
            email="existing@test.com",
            nickname="기존유저",
            password="test1234",
        )

        response = self.client.post(
            "/api/accounts/guest/",
            {"nickname": "기존유저"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        # 접미사가 추가되어야 함
        self.assertTrue(response.data["nickname"].startswith("기존유저_"))

    def test_get_guest_me(self):
        """게스트 정보 조회 API 테스트"""
        # 세션 생성
        create_response = self.client.post(
            "/api/accounts/guest/",
            {"nickname": "조회테스트"},
            format="json",
        )
        token = create_response.data["token"]

        # 토큰으로 조회
        response = self.client.get(
            "/api/accounts/guest/me/",
            HTTP_X_GUEST_TOKEN=token,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["nickname"], "조회테스트")
        self.assertTrue(response.data["is_guest"])

    def test_get_guest_me_no_token(self):
        """토큰 없이 게스트 정보 조회 실패 테스트"""
        response = self.client.get("/api/accounts/guest/me/")
        self.assertEqual(response.status_code, 401)

    def test_delete_guest_session(self):
        """게스트 세션 종료 API 테스트"""
        # 세션 생성
        create_response = self.client.post(
            "/api/accounts/guest/",
            {"nickname": "삭제테스트"},
            format="json",
        )
        token = create_response.data["token"]

        # 세션 종료
        response = self.client.delete(
            "/api/accounts/guest/me/",
            HTTP_X_GUEST_TOKEN=token,
        )

        self.assertEqual(response.status_code, 200)

        # 다시 조회하면 실패
        response = self.client.get(
            "/api/accounts/guest/me/",
            HTTP_X_GUEST_TOKEN=token,
        )
        self.assertEqual(response.status_code, 401)
