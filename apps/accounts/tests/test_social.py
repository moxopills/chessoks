"""소셜 로그인 E2E 테스트"""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from rest_framework import serializers, status
from rest_framework.test import APIClient

from apps.accounts.models import SocialUser

User = get_user_model()


class SocialUserModelTest(TestCase):
    """SocialUser 모델 테스트"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com", nickname="테스트", password="Pass123!"
        )

    def test_create_social_user(self):
        """소셜 유저 생성"""
        social = SocialUser.objects.create(
            user=self.user,
            provider="google",
            provider_user_id="g_12345",
            extra_data={"email": "test@gmail.com", "name": "Test User"},
        )

        self.assertEqual(social.user, self.user)
        self.assertEqual(social.provider, "google")
        self.assertEqual(social.provider_user_id, "g_12345")
        self.assertEqual(social.extra_data["email"], "test@gmail.com")
        self.assertIsNotNone(social.created_at)
        self.assertIsNotNone(social.updated_at)

    def test_provider_choices(self):
        """모든 제공자 생성 가능"""
        providers = ["google", "github", "kakao", "naver"]

        for idx, provider in enumerate(providers):
            social = SocialUser.objects.create(
                user=self.user, provider=provider, provider_user_id=f"{provider}_{idx}"
            )
            self.assertEqual(social.provider, provider)
            self.assertEqual(
                social.get_provider_display(), dict(SocialUser.PROVIDER_CHOICES)[provider]
            )

    def test_unique_provider_user_id(self):
        """provider + provider_user_id 조합 중복 방지"""
        SocialUser.objects.create(user=self.user, provider="google", provider_user_id="g_123")

        with self.assertRaises(IntegrityError):
            SocialUser.objects.create(user=self.user, provider="google", provider_user_id="g_123")

    def test_multiple_providers_per_user(self):
        """한 유저가 여러 제공자 연동 가능"""
        SocialUser.objects.create(user=self.user, provider="google", provider_user_id="g_1")
        SocialUser.objects.create(user=self.user, provider="github", provider_user_id="gh_1")

        self.assertEqual(self.user.social_users.count(), 2)

    def test_str_representation(self):
        """문자열 표현"""
        social = SocialUser.objects.create(
            user=self.user, provider="google", provider_user_id="g_123"
        )

        self.assertEqual(str(social), "테스트 - Google")

    def test_cascade_delete(self):
        """유저 삭제 시 소셜 계정도 삭제"""
        SocialUser.objects.create(user=self.user, provider="google", provider_user_id="g_123")

        self.assertEqual(SocialUser.objects.count(), 1)
        self.user.delete()
        self.assertEqual(SocialUser.objects.count(), 0)


class SocialLoginE2ETestCase(TestCase):
    """소셜 로그인 E2E 테스트"""

    def setUp(self):
        self.client = APIClient()
        self.mock_patcher = patch(
            "apps.accounts.services.social_service.SocialAuthService.get_provider_user_info"
        )
        self.mock_provider = self.mock_patcher.start()

    def tearDown(self):
        self.mock_patcher.stop()

    def _social_login(self, provider="google", nickname=None):
        """소셜 로그인 헬퍼"""
        data = {"provider": provider, "access_token": "mock_token_1234567890"}
        if nickname:
            data["nickname"] = nickname
        return self.client.post("/api/accounts/social/login/", data, format="json")

    def test_new_user_signup(self):
        """신규 유저 즉시 가입"""
        self.mock_provider.return_value = {"id": "g_123", "email": "new@gmail.com", "name": "New"}

        response = self._social_login(nickname="신규")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user"]["nickname"], "신규")
        self.assertTrue(SocialUser.objects.filter(provider="google").exists())

    def test_nickname_required(self):
        """닉네임 필수"""
        self.mock_provider.return_value = {"id": "g_456", "email": "test@gmail.com", "name": "Test"}

        response = self._social_login()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("nickname", response.data)

    def test_existing_user_link(self):
        """기존 유저 자동 연동"""
        User.objects.create_user(email="exist@gmail.com", nickname="기존", password="Pass123!")
        self.mock_provider.return_value = {
            "id": "g_789",
            "email": "exist@gmail.com",
            "name": "Exist",
        }

        response = self._social_login()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user"]["nickname"], "기존")

    def test_token_update(self):
        """재로그인 시 updated_at 업데이트"""
        self.mock_provider.return_value = {
            "id": "g_111",
            "email": "token@gmail.com",
            "name": "Token",
        }

        self._social_login(nickname="토큰")
        social = SocialUser.objects.get()
        old_updated_at = social.updated_at

        # 약간의 지연을 위해
        import time
        time.sleep(0.01)

        self.client.post(
            "/api/accounts/social/login/",
            {"provider": "google", "access_token": "new_token_0987654321"},
            format="json",
        )
        social.refresh_from_db()
        new_updated_at = social.updated_at

        self.assertGreater(new_updated_at, old_updated_at)

    def test_list_accounts(self):
        """계정 목록 조회"""
        self.mock_provider.return_value = {"id": "g_222", "email": "list@gmail.com", "name": "List"}

        self._social_login(nickname="목록")
        response = self.client.get("/api/accounts/social/accounts/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_unlink_with_password(self):
        """비밀번호 있으면 연동 해제 가능"""
        self.mock_provider.return_value = {
            "id": "g_333",
            "email": "unlink@gmail.com",
            "name": "Unlink",
        }

        response = self._social_login(nickname="연동해제")
        user = User.objects.get(id=response.data["user"]["id"])
        user.set_password("Pass123!")
        user.save()

        # 비밀번호 설정 후 세션 유지를 위해 재인증
        self.client.force_authenticate(user=user)

        response = self.client.delete(
            "/api/accounts/social/accounts/unlink/", {"provider": "google"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_prevent_last_unlink(self):
        """마지막 수단 해제 방지"""
        self.mock_provider.return_value = {"id": "g_444", "email": "last@gmail.com", "name": "Last"}

        self._social_login(nickname="마지막")
        response = self.client.delete(
            "/api/accounts/social/accounts/unlink/", {"provider": "google"}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("마지막", str(response.data))


class SocialAuthServiceTest(TestCase):
    """SocialAuthService 유닛 테스트"""

    @patch("apps.accounts.services.social_service.requests.get")
    def test_google_user_info_success(self, mock_get):
        """Google OAuth - 성공"""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "123456",
            "email": "user@gmail.com",
            "name": "Test User",
        }

        from apps.accounts.services.social_service import SocialAuthService

        result = SocialAuthService.get_provider_user_info("google", "mock_token")

        self.assertEqual(result["id"], "123456")
        self.assertEqual(result["email"], "user@gmail.com")
        self.assertEqual(result["name"], "Test User")
        mock_get.assert_called_once()
        self.assertIn("Bearer mock_token", str(mock_get.call_args))

    @patch("apps.accounts.services.social_service.requests.get")
    def test_github_user_info_success(self, mock_get):
        """GitHub OAuth - 성공"""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": 789,
            "email": "user@github.com",
            "name": "GitHub User",
            "login": "githubuser",
        }

        from apps.accounts.services.social_service import SocialAuthService

        result = SocialAuthService.get_provider_user_info("github", "mock_token")

        self.assertEqual(result["id"], "789")
        self.assertEqual(result["email"], "user@github.com")
        self.assertIn("token mock_token", str(mock_get.call_args))

    @patch("apps.accounts.services.social_service.requests.get")
    def test_kakao_user_info_success(self, mock_get):
        """Kakao OAuth - 성공"""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": 999,
            "kakao_account": {
                "email": "user@kakao.com",
                "profile": {"nickname": "카카오유저"},
            },
        }

        from apps.accounts.services.social_service import SocialAuthService

        result = SocialAuthService.get_provider_user_info("kakao", "mock_token")

        self.assertEqual(result["id"], "999")
        self.assertEqual(result["email"], "user@kakao.com")
        self.assertEqual(result["name"], "카카오유저")

    @patch("apps.accounts.services.social_service.requests.get")
    def test_naver_user_info_success(self, mock_get):
        """Naver OAuth - 성공"""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": {"id": "naver123", "email": "user@naver.com", "name": "네이버유저"}
        }

        from apps.accounts.services.social_service import SocialAuthService

        result = SocialAuthService.get_provider_user_info("naver", "mock_token")

        self.assertEqual(result["id"], "naver123")
        self.assertEqual(result["email"], "user@naver.com")
        self.assertEqual(result["name"], "네이버유저")

    def test_invalid_provider(self):
        """지원하지 않는 provider"""
        from apps.accounts.services.social_service import SocialAuthService

        with self.assertRaises(ValueError) as ctx:
            SocialAuthService.get_provider_user_info("invalid", "token")
        self.assertIn("지원하지 않는 provider", str(ctx.exception))

    @patch("apps.accounts.services.social_service.requests.get")
    def test_oauth_401_error(self, mock_get):
        """OAuth 401 - 유효하지 않은 토큰"""
        mock_response = mock_get.return_value
        mock_response.status_code = 401

        from apps.accounts.services.social_service import SocialAuthService

        with self.assertRaises(ValueError) as ctx:
            SocialAuthService.get_provider_user_info("google", "invalid_token")
        self.assertIn("유효하지 않은 access token", str(ctx.exception))

    @patch("apps.accounts.services.social_service.requests.get")
    def test_oauth_500_error(self, mock_get):
        """OAuth 500 - 서버 오류"""
        mock_response = mock_get.return_value
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        from apps.accounts.services.social_service import SocialAuthService

        with self.assertRaises(ValueError) as ctx:
            SocialAuthService.get_provider_user_info("google", "token")
        self.assertIn("사용자 정보를 가져올 수 없습니다", str(ctx.exception))

    @patch("apps.accounts.services.social_service.requests.get")
    def test_oauth_request_exception(self, mock_get):
        """OAuth 네트워크 오류"""
        import requests

        mock_get.side_effect = requests.exceptions.RequestException("Connection timeout")

        from apps.accounts.services.social_service import SocialAuthService

        with self.assertRaises(ValueError) as ctx:
            SocialAuthService.get_provider_user_info("google", "token")
        self.assertIn("서버와 통신할 수 없습니다", str(ctx.exception))

    @patch("apps.accounts.services.social_service.requests.get")
    def test_github_null_email(self, mock_get):
        """GitHub - 이메일 없는 경우"""
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": 111,
            "email": None,
            "name": None,
            "login": "nomail",
        }

        from apps.accounts.services.social_service import SocialAuthService

        result = SocialAuthService.get_provider_user_info("github", "token")

        self.assertEqual(result["email"], "")
        self.assertEqual(result["name"], "nomail")

    def test_nickname_duplicate_on_create(self):
        """신규 유저 생성 시 닉네임 중복"""
        from apps.accounts.services.social_service import SocialAuthService

        User.objects.create_user(email="existing@test.com", nickname="중복닉", password="Pass123!")

        provider_data = {"id": "new123", "email": "new@gmail.com", "name": "New User"}

        with self.assertRaises(serializers.ValidationError) as ctx:
            SocialAuthService.create_or_update_user("google", provider_data, nickname="중복닉")

        self.assertIn("nickname", str(ctx.exception))
