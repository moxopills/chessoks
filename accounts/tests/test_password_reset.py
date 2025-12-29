"""비밀번호 재설정 테스트"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import PasswordResetToken
from accounts.services.password_service import PasswordResetService

User = get_user_model()


class PasswordResetTokenModelTest(TestCase):
    """PasswordResetToken 모델 테스트"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com", nickname="테스터", password="Pass123!"
        )

    def test_token_generation_unique(self):
        """토큰 생성 시 고유값"""
        token1 = PasswordResetToken.generate_token()
        token2 = PasswordResetToken.generate_token()
        self.assertNotEqual(token1, token2)
        self.assertTrue(len(token1) > 40)

    def test_token_expiration(self):
        """토큰 만료 확인"""
        # 만료된 토큰
        expired_token = PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() - timedelta(hours=1),
        )
        self.assertTrue(expired_token.is_expired)
        self.assertFalse(expired_token.is_valid)

        # 유효한 토큰
        valid_token = PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertFalse(valid_token.is_expired)
        self.assertTrue(valid_token.is_valid)

    def test_used_token_invalid(self):
        """사용된 토큰은 유효하지 않음"""
        token = PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
            is_used=True,
        )
        self.assertFalse(token.is_valid)

    def test_str_representation(self):
        """문자열 표현"""
        token = PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertIn(self.user.email, str(token))


class PasswordResetServiceTest(TestCase):
    """PasswordResetService 테스트"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="service@example.com", nickname="서비스", password="Pass123!"
        )

    def test_create_reset_token_success(self):
        """존재하는 유저에 대한 토큰 생성"""
        token = PasswordResetService.create_reset_token(self.user.email)

        self.assertIsNotNone(token)
        self.assertEqual(token.user, self.user)
        self.assertFalse(token.is_used)
        self.assertEqual(len(mail.outbox), 1)  # 이메일 전송 확인
        self.assertIn("비밀번호 재설정", mail.outbox[0].subject)

    def test_create_reset_token_nonexistent_user(self):
        """존재하지 않는 유저에 대한 토큰 생성 (보안)"""
        token = PasswordResetService.create_reset_token("nonexistent@example.com")

        self.assertIsNone(token)
        self.assertEqual(len(mail.outbox), 0)  # 이메일 미전송

    def test_invalidate_old_tokens(self):
        """기존 토큰 무효화"""
        # 첫 번째 토큰 생성
        PasswordResetService.create_reset_token(self.user.email)
        old_token = PasswordResetToken.objects.first()

        # 두 번째 토큰 생성
        PasswordResetService.create_reset_token(self.user.email)

        # 이전 토큰이 무효화되었는지 확인
        old_token.refresh_from_db()
        self.assertTrue(old_token.is_used)

    def test_reset_password_success(self):
        """비밀번호 재설정 성공"""
        token_obj = PasswordResetService.create_reset_token(self.user.email)

        success, message = PasswordResetService.reset_password(token_obj.token, "NewPass123!")

        self.assertTrue(success)
        self.assertIn("재설정", message)

        # 비밀번호 변경 확인
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewPass123!"))

        # 토큰 사용됨 확인
        token_obj.refresh_from_db()
        self.assertTrue(token_obj.is_used)
        self.assertIsNotNone(token_obj.used_at)

    def test_reset_password_invalid_token(self):
        """유효하지 않은 토큰"""
        success, message = PasswordResetService.reset_password("invalid_token", "NewPass123!")

        self.assertFalse(success)
        self.assertIn("유효하지 않은", message)

    def test_reset_password_expired_token(self):
        """만료된 토큰"""
        token_obj = PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() - timedelta(hours=1),
        )

        success, message = PasswordResetService.reset_password(token_obj.token, "NewPass123!")

        self.assertFalse(success)
        self.assertIn("만료", message)

    def test_reset_password_used_token(self):
        """이미 사용된 토큰"""
        token_obj = PasswordResetService.create_reset_token(self.user.email)

        # 첫 번째 사용
        PasswordResetService.reset_password(token_obj.token, "NewPass123!")

        # 두 번째 사용 시도
        success, message = PasswordResetService.reset_password(token_obj.token, "Another123!")

        self.assertFalse(success)
        self.assertIn("사용된", message)


class PasswordResetE2ETest(TestCase):
    """비밀번호 재설정 E2E 테스트"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="e2e@example.com", nickname="E2E", password="OldPass123!"
        )

    def test_complete_password_reset_flow(self):
        """완전한 비밀번호 재설정 플로우"""
        # 1. 재설정 요청
        response = self.client.post(
            "/accounts/password-reset/request/",
            {"email": self.user.email},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

        # 2. 토큰 추출
        token = PasswordResetToken.objects.first()
        self.assertIsNotNone(token)

        # 3. 비밀번호 재설정
        response = self.client.post(
            "/accounts/password-reset/confirm/",
            {
                "token": token.token,
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 4. 새 비밀번호로 로그인 확인
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewPass123!"))

    def test_nonexistent_email_security(self):
        """존재하지 않는 이메일도 동일한 응답 (보안)"""
        response = self.client.post(
            "/accounts/password-reset/request/",
            {"email": "nonexistent@example.com"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 0)

    def test_expired_token_rejection(self):
        """만료된 토큰 거부"""
        expired_token = PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() - timedelta(hours=1),
        )

        response = self.client.post(
            "/accounts/password-reset/confirm/",
            {
                "token": expired_token.token,
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_token_reuse_prevention(self):
        """토큰 재사용 방지"""
        token = PasswordResetService.create_reset_token(self.user.email)

        # 첫 번째 사용
        self.client.post(
            "/accounts/password-reset/confirm/",
            {
                "token": token.token,
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )

        # 두 번째 사용 시도
        response = self.client.post(
            "/accounts/password-reset/confirm/",
            {
                "token": token.token,
                "new_password": "Another123!",
                "new_password2": "Another123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_validation(self):
        """비밀번호 검증 규칙"""
        token = PasswordResetService.create_reset_token(self.user.email)

        # 너무 짧음
        response = self.client.post(
            "/accounts/password-reset/confirm/",
            {"token": token.token, "new_password": "Short1!", "new_password2": "Short1!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 대문자 없음
        token2 = PasswordResetService.create_reset_token(self.user.email)
        response = self.client.post(
            "/accounts/password-reset/confirm/",
            {
                "token": token2.token,
                "new_password": "lowercase123!",
                "new_password2": "lowercase123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 특수문자 없음
        token3 = PasswordResetService.create_reset_token(self.user.email)
        response = self.client.post(
            "/accounts/password-reset/confirm/",
            {
                "token": token3.token,
                "new_password": "NoSpecial123",
                "new_password2": "NoSpecial123",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_mismatch(self):
        """비밀번호 불일치"""
        token = PasswordResetService.create_reset_token(self.user.email)

        response = self.client.post(
            "/accounts/password-reset/confirm/",
            {
                "token": token.token,
                "new_password": "NewPass123!",
                "new_password2": "Different123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
