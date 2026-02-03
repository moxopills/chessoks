"""소셜 로그인 테스트"""

from unittest.mock import patch

from django.db import IntegrityError

from rest_framework import serializers, status

from apps.accounts.models import SocialUser
from apps.accounts.tests.test_auth import BaseAPITestCase, BaseTestCase


class SocialUserModelTest(BaseTestCase):
    """SocialUser 모델 테스트"""

    def setUp(self):
        self.user = self.create_user(email="test@example.com", nickname="테스트")

    def test_create_social_user(self):
        """소셜 유저 생성"""
        social = SocialUser.objects.create(
            user=self.user,
            provider="kakao",
            provider_user_id="k_12345",
            extra_data={"email": "test@kakao.com", "name": "Test User"},
        )

        self.assertEqual(social.user, self.user)
        self.assertEqual(social.provider, "kakao")
        self.assertEqual(social.provider_user_id, "k_12345")
        self.assertEqual(social.extra_data["email"], "test@kakao.com")
        self.assertIsNotNone(social.created_at)
        self.assertIsNotNone(social.updated_at)

    def test_provider_choices(self):
        """Kakao/Naver 제공자만 허용"""
        providers = ["kakao", "naver"]

        for idx, provider in enumerate(providers):
            user = self.create_user(email=f"test{idx}@example.com", nickname=f"테스트{idx}")
            social = SocialUser.objects.create(
                user=user, provider=provider, provider_user_id=f"{provider}_{idx}"
            )
            self.assertEqual(social.provider, provider)
            self.assertEqual(
                social.get_provider_display(), dict(SocialUser.PROVIDER_CHOICES)[provider]
            )

    def test_unique_provider_user_id(self):
        """provider + provider_user_id 조합 중복 방지"""
        SocialUser.objects.create(user=self.user, provider="kakao", provider_user_id="k_123")

        with self.assertRaises(IntegrityError):
            SocialUser.objects.create(user=self.user, provider="kakao", provider_user_id="k_123")

    def test_single_provider_per_user(self):
        """한 유저당 소셜 계정 1개만 허용"""
        SocialUser.objects.create(user=self.user, provider="kakao", provider_user_id="k_1")

        with self.assertRaises(IntegrityError):
            SocialUser.objects.create(user=self.user, provider="naver", provider_user_id="n_1")

    def test_str_representation(self):
        """문자열 표현"""
        social = SocialUser.objects.create(
            user=self.user, provider="kakao", provider_user_id="k_123"
        )

        self.assertEqual(str(social), "테스트 - Kakao")

    def test_cascade_delete(self):
        """유저 삭제 시 소셜 계정도 삭제"""
        SocialUser.objects.create(user=self.user, provider="kakao", provider_user_id="k_123")

        self.assertEqual(SocialUser.objects.count(), 1)
        self.user.delete()
        self.assertEqual(SocialUser.objects.count(), 0)


class SocialAuthServiceTest(BaseTestCase):
    """SocialAuthService 유닛 테스트"""

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
            SocialAuthService.get_provider_user_info("kakao", "invalid_token")
        self.assertIn("유효하지 않은 access token", str(ctx.exception))

    @patch("apps.accounts.services.social_service.requests.get")
    def test_oauth_500_error(self, mock_get):
        """OAuth 500 - 서버 오류"""
        mock_response = mock_get.return_value
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        from apps.accounts.services.social_service import SocialAuthService

        with self.assertRaises(ValueError) as ctx:
            SocialAuthService.get_provider_user_info("kakao", "token")
        self.assertIn("사용자 정보를 가져올 수 없습니다", str(ctx.exception))

    @patch("apps.accounts.services.social_service.requests.get")
    def test_oauth_request_exception(self, mock_get):
        """OAuth 네트워크 오류"""
        import requests

        mock_get.side_effect = requests.exceptions.RequestException("Connection timeout")

        from apps.accounts.services.social_service import SocialAuthService

        with self.assertRaises(ValueError) as ctx:
            SocialAuthService.get_provider_user_info("kakao", "token")
        self.assertIn("서버와 통신할 수 없습니다", str(ctx.exception))

    def test_nickname_duplicate_on_create(self):
        """신규 유저 생성 시 닉네임 중복"""
        from apps.accounts.services.social_service import SocialAuthService

        self.create_user(email="existing@test.com", nickname="중복닉")

        provider_data = {"id": "new123", "email": "new@kakao.com", "name": "New User"}

        with self.assertRaises(serializers.ValidationError) as ctx:
            SocialAuthService.create_or_update_user("kakao", provider_data, nickname="중복닉")

        self.assertIn("nickname", str(ctx.exception))

    def test_existing_user_with_social_blocked(self):
        """이미 소셜 연동된 유저는 다른 소셜 추가 불가"""
        from apps.accounts.services.social_service import SocialAuthService

        user = self.create_user(email="linked@test.com", nickname="연동유저")
        SocialUser.objects.create(user=user, provider="kakao", provider_user_id="k_linked")

        provider_data = {"id": "n_new", "email": "linked@test.com", "name": "Naver User"}

        with self.assertRaises(serializers.ValidationError) as ctx:
            SocialAuthService.create_or_update_user("naver", provider_data, nickname=None)

        self.assertIn("provider", str(ctx.exception))


class SocialViewsEdgeCaseTest(BaseAPITestCase):
    """소셜 뷰 엣지 케이스 테스트"""

    def test_list_accounts_without_auth(self):
        """인증 없이 소셜 계정 목록 조회"""
        response = self.client.get("/api/accounts/social/accounts/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unlink_without_auth(self):
        """인증 없이 연동 해제 시도"""
        response = self.client.delete(
            "/api/accounts/social/accounts/unlink/", {"provider": "kakao"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unlink_nonexistent_provider(self):
        """연동되지 않은 provider 해제 시도"""
        user = self.create_user()
        self.client.force_authenticate(user=user)

        response = self.client.delete(
            "/api/accounts/social/accounts/unlink/", {"provider": "kakao"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
