"""소셜 로그인 E2E 테스트"""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import SocialUser

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
            access_token="token_abc",
            extra_data={"email": "test@gmail.com", "name": "Test User"},
        )

        self.assertEqual(social.user, self.user)
        self.assertEqual(social.provider, "google")
        self.assertEqual(social.provider_user_id, "g_12345")
        self.assertEqual(social.access_token, "token_abc")
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

    def test_token_not_expired_when_no_expiry(self):
        """만료 시간 없으면 만료되지 않음"""
        social = SocialUser.objects.create(
            user=self.user, provider="google", provider_user_id="g_123", token_expires_at=None
        )

        self.assertFalse(social.is_token_expired)

    def test_token_not_expired_when_future(self):
        """만료 시간이 미래면 만료되지 않음"""
        future = timezone.now() + timedelta(hours=1)
        social = SocialUser.objects.create(
            user=self.user, provider="google", provider_user_id="g_123", token_expires_at=future
        )

        self.assertFalse(social.is_token_expired)

    def test_token_expired_when_past(self):
        """만료 시간이 과거면 만료됨"""
        past = timezone.now() - timedelta(hours=1)
        social = SocialUser.objects.create(
            user=self.user, provider="google", provider_user_id="g_123", token_expires_at=past
        )

        self.assertTrue(social.is_token_expired)

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
            "accounts.services.social_service.SocialAuthService.get_provider_user_info"
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
        """재로그인 시 토큰 업데이트"""
        self.mock_provider.return_value = {
            "id": "g_111",
            "email": "token@gmail.com",
            "name": "Token",
        }

        self._social_login(nickname="토큰")
        old_token = SocialUser.objects.get().access_token

        self.client.post(
            "/api/accounts/social/login/",
            {"provider": "google", "access_token": "new_token_0987654321"},
            format="json",
        )
        new_token = SocialUser.objects.get().access_token

        self.assertNotEqual(old_token, new_token)

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
