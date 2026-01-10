from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import LiveServerTestCase, TestCase
from django.utils import timezone

from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory, APITestCase

from apps.accounts.models import EmailVerificationToken, PasswordResetToken
from apps.accounts.serializers import ProfileUpdateSerializer, UserSignUpSerializer

User = get_user_model()

# 테스트 상수
TEST_PASSWORD = "Pass123!"
TEST_EMAIL = "test@test.com"
TEST_NICKNAME = "테스터"


class BaseTestCase(TestCase):
    """공통 테스트 베이스 클래스"""

    @classmethod
    def setUpTestData(cls):
        """테스트 데이터 공통 설정"""
        cls.valid_signup_data = {
            "email": "test@example.com",
            "nickname": "테스터",
            "bio": "자기소개입니다",
            "password": TEST_PASSWORD,
            "password2": TEST_PASSWORD,
        }

    def create_user(
        self,
        email=TEST_EMAIL,
        nickname=TEST_NICKNAME,
        password=TEST_PASSWORD,
        email_verified=False,
    ):
        """테스트 유저 생성 헬퍼"""
        user = User.objects.create_user(email=email, nickname=nickname, password=password)
        if email_verified:
            user.email_verified = True
            user.save(update_fields=["email_verified"])
        return user

    def create_verified_user(self, email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD):
        """이메일 인증된 테스트 유저 생성"""
        return self.create_user(email=email, nickname=nickname, password=password, email_verified=True)

    def create_test_image(self, filename="test.png"):
        """테스트용 이미지 파일 생성"""
        png_data = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
            b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        return SimpleUploadedFile(filename, png_data, content_type="image/png")

    @contextmanager
    def mock_s3(self):
        """S3 mock context manager"""
        from moto import mock_aws

        with patch("apps.core.S3.uploader.settings") as mock_settings:
            mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
            mock_settings.AWS_S3_REGION = "ap-northeast-2"
            mock_settings.AWS_S3_ACCESS_KEY_ID = "test"
            mock_settings.AWS_S3_SECRET_ACCESS_KEY = "test"

            with mock_aws():
                import boto3

                s3_client = boto3.client(
                    "s3",
                    region_name="ap-northeast-2",
                    aws_access_key_id="test",
                    aws_secret_access_key="test",
                )
                s3_client.create_bucket(
                    Bucket="test-bucket",
                    CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
                )

                with patch(
                    "apps.core.S3.uploader.s3_uploader.get_s3_client", return_value=s3_client
                ):
                    yield s3_client


class BaseAPITestCase(APITestCase, BaseTestCase):
    """API 테스트용 베이스 클래스"""

    pass


class AuthE2ETestCase(LiveServerTestCase):
    """인증 E2E 테스트"""

    def setUp(self):
        self.client = APIClient()
        cache.clear()

    def tearDown(self):
        cache.clear()
        User.objects.all().delete()

    def test_complete_auth_flow(self):
        """완전한 인증 플로우 E2E 테스트: 회원가입 → 로그인 → 유저 정보 조회 → 로그아웃"""

        # 1. 회원가입
        signup_data = {
            "email": "e2e@test.com",
            "nickname": "E2E테스터",
            "password": "TestPass123!",
            "password2": "TestPass123!",
        }
        response = self.client.post("/api/accounts/signup/", signup_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("message", response.data)
        self.assertIn("email", response.data)
        self.assertEqual(response.data["email"], signup_data["email"])

        # 이메일 인증 설정 (E2E 테스트를 위해)
        user = User.objects.get(email="e2e@test.com")
        user.email_verified = True
        user.save()

        # 2. 로그인
        login_data = {"email": "e2e@test.com", "password": "TestPass123!"}
        response = self.client.post("/api/accounts/login/", login_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("user", response.data)

        # 3. 현재 유저 정보 조회 (로그인 상태)
        response = self.client.get("/api/accounts/me/", format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], signup_data["email"])
        self.assertEqual(response.data["nickname"], signup_data["nickname"])

        # 4. 로그아웃
        response = self.client.post("/api/accounts/logout/", format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 5. 로그아웃 후 유저 정보 조회 실패 확인
        response = self.client.get("/api/accounts/me/", format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_login_failure_lockout_flow(self):
        """로그인 실패 → 잠금 → 해제 플로우 E2E 테스트"""

        # 1. 유저 생성
        User.objects.create_user(
            email="locktest@test.com", nickname="잠금테스트", password="CorrectPass123!"
        )

        wrong_data = {"email": "locktest@test.com", "password": "WrongPass!"}

        # 2. 첫 번째 실패 (남은 시도: 2회)
        response = self.client.post("/api/accounts/login/", wrong_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("남은 시도: 2회", response.data["non_field_errors"][0])

        # 3. 두 번째 실패 (남은 시도: 1회)
        response = self.client.post("/api/accounts/login/", wrong_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("남은 시도: 1회", response.data["non_field_errors"][0])

        # 4. 세 번째 실패 → 잠금
        response = self.client.post("/api/accounts/login/", wrong_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn("5분 후", response.data["non_field_errors"][0])

        # 5. 잠금 상태에서 올바른 비밀번호로도 로그인 불가
        correct_data = {"email": "locktest@test.com", "password": "CorrectPass123!"}
        response = self.client.post("/api/accounts/login/", correct_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

        # 6. 캐시 수동 삭제 (실제로는 5분 대기)
        cache.delete("login_lock:locktest@test.com")
        cache.delete("login_fail:locktest@test.com")

        # 7. 잠금 해제 후 올바른 비밀번호로 로그인 성공
        response = self.client.post("/api/accounts/login/", correct_data, format="json")
        # 로그인 성공 확인 (이메일 인증이 안되어 있으면 403일 수 있음)
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN])

    def test_duplicate_signup_prevention(self):
        """중복 회원가입 방지 E2E 테스트"""

        signup_data = {
            "email": "duplicate@test.com",
            "nickname": "중복테스트",
            "password": "TestPass123!",
            "password2": "TestPass123!",
        }

        # 1. 첫 번째 회원가입 성공
        response = self.client.post("/api/accounts/signup/", signup_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 2. 같은 이메일로 재가입 시도 → 실패
        response = self.client.post("/api/accounts/signup/", signup_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

        # 3. 다른 이메일, 같은 닉네임으로 재가입 시도 → 실패
        signup_data2 = {
            "email": "another@test.com",
            "nickname": "중복테스트",
            "password": "TestPass123!",
            "password2": "TestPass123!",
        }
        response = self.client.post("/api/accounts/signup/", signup_data2, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("nickname", response.data)

    def test_password_validation_flow(self):
        """비밀번호 검증 E2E 테스트"""

        base_data = {
            "email": "pwtest@test.com",
            "nickname": "비밀번호테스트",
        }

        # 1. 8자 미만
        data = {**base_data, "password": "Test1!", "password2": "Test1!"}
        response = self.client.post("/api/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 2. 대문자 없음
        data = {**base_data, "password": "testpass123!", "password2": "testpass123!"}
        response = self.client.post("/api/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 3. 특수문자 없음
        data = {**base_data, "password": "TestPass123", "password2": "TestPass123"}
        response = self.client.post("/api/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 4. 비밀번호 불일치
        data = {**base_data, "password": "TestPass123!", "password2": "Different!"}
        response = self.client.post("/api/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 5. 모든 조건 만족 → 성공
        data = {**base_data, "password": "TestPass123!", "password2": "TestPass123!"}
        response = self.client.post("/api/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_user_session_persistence(self):
        """세션 유지 E2E 테스트"""

        # 1. 회원가입
        signup_data = {
            "email": "session@test.com",
            "nickname": "세션테스트",
            "password": "TestPass123!",
            "password2": "TestPass123!",
        }
        self.client.post("/api/accounts/signup/", signup_data, format="json")

        # 이메일 인증 설정 (E2E 테스트를 위해)
        user = User.objects.get(email="session@test.com")
        user.email_verified = True
        user.save()

        # 2. 로그인
        login_data = {"email": "session@test.com", "password": "TestPass123!"}
        response = self.client.post("/api/accounts/login/", login_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 3. 여러 번 /me/ 호출해도 세션 유지
        for _ in range(5):
            response = self.client.get("/api/accounts/me/", format="json")
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["email"], "session@test.com")

        # 4. 로그아웃
        self.client.post("/api/accounts/logout/", format="json")

        # 5. 로그아웃 후 세션 무효화 확인
        response = self.client.get("/api/accounts/me/", format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class UserSignUpSerializerTest(BaseTestCase):
    """회원가입 시리얼라이저 유닛 테스트"""

    def _assert_invalid_password(self, password, expected_error):
        """비밀번호 검증 헬퍼"""
        data = self.valid_signup_data.copy()
        data["password"] = data["password2"] = password
        serializer = UserSignUpSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)
        self.assertIn(expected_error, str(serializer.errors["password"][0]))

    def test_valid_signup_data(self):
        """정상 데이터로 회원가입 성공"""
        serializer = UserSignUpSerializer(data=self.valid_signup_data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.email, self.valid_signup_data["email"])
        self.assertEqual(user.nickname, self.valid_signup_data["nickname"])
        self.assertEqual(user.bio, self.valid_signup_data["bio"])

    def test_password_too_short(self):
        """비밀번호 8자 미만 검증"""
        self._assert_invalid_password("Test1!", "최소 8자")

    def test_password_no_uppercase(self):
        """비밀번호 대문자 없음 검증"""
        self._assert_invalid_password("testpass123!", "대문자")

    def test_password_no_special_char(self):
        """비밀번호 특수문자 없음 검증"""
        self._assert_invalid_password("TestPass123", "특수문자")

    def test_duplicate_email(self):
        """이메일 중복 검증"""
        self.create_user(email="dup@test.com")
        data = self.valid_signup_data.copy()
        data["email"] = "dup@test.com"
        serializer = UserSignUpSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)

    def test_duplicate_nickname(self):
        """닉네임 중복 검증"""
        self.create_user(nickname="중복닉네임")
        data = self.valid_signup_data.copy()
        data["nickname"] = "중복닉네임"
        serializer = UserSignUpSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("nickname", serializer.errors)

    def test_signup_with_scheduled_deletion_email(self):
        """탈퇴 예약된 이메일로 회원가입 시도 (유예 기간 내)"""
        user = self.create_user(email="scheduled@test.com")
        user.is_active = False
        user.scheduled_deletion_at = timezone.now() + timedelta(days=1)
        user.save()

        data = self.valid_signup_data.copy()
        data["email"] = "scheduled@test.com"
        serializer = UserSignUpSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)
        self.assertIn("탈퇴 예약", str(serializer.errors["email"][0]))

    def test_signup_with_expired_scheduled_deletion_email(self):
        """유예 기간 만료된 이메일로 회원가입 - 기존 계정 삭제 후 허용"""
        old_user = self.create_user(email="expired@test.com", nickname="expireduser")
        old_user.is_active = False
        old_user.scheduled_deletion_at = timezone.now() - timedelta(hours=1)
        old_user.save()
        old_user_id = old_user.id

        data = self.valid_signup_data.copy()
        data["email"] = "expired@test.com"
        data["nickname"] = "newuser123"
        serializer = UserSignUpSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)

        # 기존 계정이 삭제되었는지 확인
        self.assertFalse(User.objects.filter(id=old_user_id).exists())

    def test_signup_with_expired_scheduled_deletion_nickname(self):
        """유예 기간 만료된 닉네임으로 회원가입 - 기존 계정 삭제 후 허용"""
        old_user = self.create_user(email="old@test.com", nickname="expirednick")
        old_user.is_active = False
        old_user.scheduled_deletion_at = timezone.now() - timedelta(hours=1)
        old_user.save()
        old_user_id = old_user.id

        data = self.valid_signup_data.copy()
        data["email"] = "newuser@test.com"
        data["nickname"] = "expirednick"
        serializer = UserSignUpSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)

        # 기존 계정이 삭제되었는지 확인
        self.assertFalse(User.objects.filter(id=old_user_id).exists())


class ProfileUpdateSerializerTest(BaseTestCase):
    """프로필 수정 시리얼라이저 유닛 테스트"""

    def setUp(self):
        self.user = self.create_user(email="user@test.com", nickname="원본닉네임")
        self.other_user = self.create_user(email="other@test.com", nickname="다른유저")
        self.factory = APIRequestFactory()

    def _get_serializer(self, data, user=None):
        """시리얼라이저 헬퍼"""
        user = user or self.user
        request = self.factory.patch("/accounts/profile/")
        request.user = user
        return ProfileUpdateSerializer(user, data=data, partial=True, context={"request": request})

    def test_update_nickname_success(self):
        """닉네임 변경 성공"""
        serializer = self._get_serializer({"nickname": "새로운닉네임"})
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.save().nickname, "새로운닉네임")

    def test_update_bio_and_avatar(self):
        """자기소개와 아바타 URL 변경"""
        data = {"bio": "새로운 자기소개", "avatar_url": "https://example.com/avatar.jpg"}
        serializer = self._get_serializer(data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.bio, "새로운 자기소개")
        self.assertEqual(user.avatar_url, "https://example.com/avatar.jpg")

    def test_duplicate_nickname_validation(self):
        """다른 유저가 사용 중인 닉네임으로 변경 시도"""
        serializer = self._get_serializer({"nickname": "다른유저"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("nickname", serializer.errors)

    def test_same_nickname_allowed(self):
        """자기 자신의 닉네임은 유지 가능"""
        serializer = self._get_serializer({"nickname": "원본닉네임"})
        self.assertTrue(serializer.is_valid())


class UserModelTest(BaseTestCase):
    """유저 모델 유닛 테스트"""

    def test_create_user_success(self):
        """일반 유저 생성 성공"""
        user = self.create_user(email="new@test.com", nickname="신규유저")
        self.assertEqual(user.email, "new@test.com")
        self.assertEqual(user.nickname, "신규유저")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_user_without_email(self):
        """이메일 없이 유저 생성 시도"""
        with self.assertRaises(ValueError) as ctx:
            User.objects.create_user(email="", nickname="테스터", password="Pass123!")
        self.assertIn("이메일은 필수", str(ctx.exception))

    def test_create_user_without_nickname(self):
        """닉네임 없이 유저 생성 시도"""
        with self.assertRaises(ValueError) as ctx:
            User.objects.create_user(email="test@test.com", nickname="", password="Pass123!")
        self.assertIn("닉네임은 필수", str(ctx.exception))

    def test_create_superuser(self):
        """슈퍼유저 생성"""
        admin = User.objects.create_superuser(
            email="admin@test.com", nickname="관리자", password="AdminPass123!"
        )
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)

    def test_user_str_representation(self):
        """유저 문자열 표현"""
        user = self.create_user(nickname="테스터")
        # User 모델의 __str__ 메서드는 nickname (email) 형식
        self.assertEqual(str(user), f"테스터 ({user.email})")

    def test_win_rate_with_games(self):
        """게임 기록이 있을 때 승률 계산"""
        user = self.create_user()
        # UserStats 모델 사용
        user.stats.games_played = 10
        user.stats.games_won = 7
        user.stats.save()
        self.assertEqual(user.stats.win_rate, 70.0)

    def test_win_rate_no_games(self):
        """게임 기록이 없을 때 승률 0"""
        user = self.create_user()
        self.assertEqual(user.stats.win_rate, 0.0)

    def test_clean_invalid_rating(self):
        """레이팅 범위 초과 검증"""
        user = self.create_user()
        # UserStats 모델의 clean 메서드 테스트
        user.stats.rating = 5000
        with self.assertRaises(ValidationError) as ctx:
            user.stats.clean()
        self.assertIn("레이팅은 0-4000", str(ctx.exception))

    def test_clean_negative_games_played(self):
        """게임 수 음수 검증"""
        user = self.create_user()
        user.stats.games_played = -5
        with self.assertRaises(ValidationError) as ctx:
            user.stats.clean()
        self.assertIn("음수가 될 수 없습니다", str(ctx.exception))

    def test_top_players(self):
        """상위 플레이어 조회"""
        from apps.accounts.models import UserStats

        u1 = self.create_user(email="p1@test.com", nickname="플1")
        u2 = self.create_user(email="p2@test.com", nickname="플2")
        u3 = self.create_user(email="p3@test.com", nickname="플3")

        # UserStats 업데이트
        UserStats.objects.filter(user=u1).update(rating=1500)
        UserStats.objects.filter(user=u2).update(rating=1800)
        UserStats.objects.filter(user=u3).update(rating=1300)

        top_players = User.objects.top_players(limit=2)
        self.assertEqual(len(top_players), 2)
        self.assertEqual(top_players[0].stats.rating, 1800)
        self.assertEqual(top_players[1].stats.rating, 1500)

    def test_active_players(self):
        """활성 플레이어 조회"""
        active = self.create_user(email="active@test.com", nickname="활성")
        inactive = self.create_user(email="inactive@test.com", nickname="비활성")
        inactive.is_active = False
        inactive.save()

        players = User.objects.active_players()
        self.assertIn(active, players)
        self.assertNotIn(inactive, players)

    def test_user_stats_str_representation(self):
        """UserStats 문자열 표현"""
        user = self.create_user(nickname="통계테스트")
        user.stats.rating = 1500
        user.stats.save()

        self.assertIn("통계테스트", str(user.stats))
        self.assertIn("1500", str(user.stats))


class PasswordResetTokenModelTest(BaseTestCase):
    """PasswordResetToken 모델 테스트"""

    def setUp(self):
        self.user = self.create_user(email="test@example.com", nickname="테스터")

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

    def test_cleanup_expired(self):
        """만료된 토큰 정리"""
        # 만료된 토큰
        PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() - timedelta(hours=1),
        )

        # 사용된 토큰
        PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
            is_used=True,
        )

        # 유효한 토큰
        valid_token = PasswordResetToken.objects.create(
            user=self.user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )

        # 정리 실행
        deleted_count = PasswordResetToken.objects.delete_expired()

        self.assertEqual(deleted_count, 2)
        self.assertTrue(PasswordResetToken.objects.filter(id=valid_token.id).exists())


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
            "/api/accounts/password-reset/request/",
            {"email": self.user.email},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # 이메일은 비동기(threading)로 전송되어 mail.outbox에서 확인 불가

        # 2. 토큰 추출 (토큰이 생성되었는지 확인)
        token = PasswordResetToken.objects.first()
        self.assertIsNotNone(token)

        # 3. 비밀번호 재설정
        response = self.client.post(
            "/api/accounts/password-reset/confirm/",
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
            "/api/accounts/password-reset/request/",
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
            "/api/accounts/password-reset/confirm/",
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
        # 토큰 생성
        response = self.client.post(
            "/api/accounts/password-reset/request/",
            {"email": self.user.email},
            format="json",
        )
        token = PasswordResetToken.objects.first()

        # 첫 번째 사용
        self.client.post(
            "/api/accounts/password-reset/confirm/",
            {
                "token": token.token,
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )

        # 두 번째 사용 시도
        response = self.client.post(
            "/api/accounts/password-reset/confirm/",
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
        # 너무 짧음
        response = self.client.post(
            "/api/accounts/password-reset/request/",
            {"email": self.user.email},
            format="json",
        )
        token1 = PasswordResetToken.objects.first()

        response = self.client.post(
            "/api/accounts/password-reset/confirm/",
            {"token": token1.token, "new_password": "Short1!", "new_password2": "Short1!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 대문자 없음
        self.client.post(
            "/api/accounts/password-reset/request/",
            {"email": self.user.email},
            format="json",
        )
        token2 = PasswordResetToken.objects.filter(is_used=False).first()

        response = self.client.post(
            "/api/accounts/password-reset/confirm/",
            {
                "token": token2.token,
                "new_password": "lowercase123!",
                "new_password2": "lowercase123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 특수문자 없음
        self.client.post(
            "/api/accounts/password-reset/request/",
            {"email": self.user.email},
            format="json",
        )
        token3 = PasswordResetToken.objects.filter(is_used=False).first()

        response = self.client.post(
            "/api/accounts/password-reset/confirm/",
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
        self.client.post(
            "/api/accounts/password-reset/request/",
            {"email": self.user.email},
            format="json",
        )
        token = PasswordResetToken.objects.first()

        response = self.client.post(
            "/api/accounts/password-reset/confirm/",
            {
                "token": token.token,
                "new_password": "NewPass123!",
                "new_password2": "Different123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class AvatarUpdateAPITestCase(BaseAPITestCase):
    """아바타 업데이트 E2E 테스트"""

    def setUp(self):
        self.user = self.create_user()
        self.client.force_authenticate(user=self.user)

    def test_avatar_update_success(self):
        """아바타 업데이트 - 성공"""
        with self.mock_s3():
            response = self.client.patch(
                "/api/accounts/profile/avatar/",
                {"avatar": self.create_test_image("avatar.png")},
                format="multipart",
            )

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn("avatar_url", response.data)

            self.user.refresh_from_db()
            self.assertIsNotNone(self.user.avatar_url)

    def test_avatar_update_replaces_old(self):
        """아바타 업데이트 - 기존 아바타 자동 교체"""
        self.user.avatar_url = "https://test-bucket.s3.ap-northeast-2.amazonaws.com/avatars/old.png"
        self.user.save()
        old_url = self.user.avatar_url

        with self.mock_s3() as s3_client:
            s3_client.put_object(Bucket="test-bucket", Key="avatars/old.png", Body=b"old")

            response = self.client.patch(
                "/api/accounts/profile/avatar/",
                {"avatar": self.create_test_image("new.png")},
                format="multipart",
            )

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.user.refresh_from_db()
            self.assertNotEqual(self.user.avatar_url, old_url)

    def test_avatar_update_without_auth(self):
        """아바타 업데이트 - 인증 없음"""
        self.client.force_authenticate(user=None)
        response = self.client.patch(
            "/api/accounts/profile/avatar/",
            {"avatar": self.create_test_image()},
            format="multipart",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_avatar_update_without_file(self):
        """아바타 업데이트 - 파일 없음"""
        response = self.client.patch("/api/accounts/profile/avatar/", {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("avatar", response.data)

    def test_avatar_update_invalid_file_type(self):
        """아바타 업데이트 - 잘못된 파일 타입"""
        txt_file = SimpleUploadedFile("test.txt", b"test", content_type="text/plain")
        response = self.client.patch(
            "/api/accounts/profile/avatar/", {"avatar": txt_file}, format="multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_avatar_update_file_too_large(self):
        """아바타 업데이트 - 파일 크기 초과"""
        large_file = SimpleUploadedFile("large.png", b"x" * (11 * 1024 * 1024), content_type="image/png")
        response = self.client.patch(
            "/api/accounts/profile/avatar/", {"avatar": large_file}, format="multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_avatar_delete_success(self):
        """아바타 삭제 - 성공"""
        self.user.avatar_url = "https://test-bucket.s3.ap-northeast-2.amazonaws.com/avatars/test.png"
        self.user.save()

        with self.mock_s3() as s3_client:
            s3_client.put_object(Bucket="test-bucket", Key="avatars/test.png", Body=b"test")

            response = self.client.delete("/api/accounts/profile/avatar/")

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.user.refresh_from_db()
            self.assertIsNone(self.user.avatar_url)

    def test_avatar_delete_no_avatar(self):
        """아바타 삭제 - 삭제할 아바타 없음"""
        self.user.avatar_url = None
        self.user.save()

        response = self.client.delete("/api/accounts/profile/avatar/")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("avatar", response.data)

    def test_avatar_delete_without_auth(self):
        """아바타 삭제 - 인증 없음"""
        self.client.force_authenticate(user=None)
        response = self.client.delete("/api/accounts/profile/avatar/")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class LoginValidationTestCase(APITestCase):
    """로그인 검증 테스트"""

    def test_login_without_email(self):
        """이메일 없이 로그인"""
        response = self.client.post("/api/accounts/login/", {"password": "Pass123!"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("이메일과 비밀번호", response.data["non_field_errors"][0])

    def test_login_without_password(self):
        """비밀번호 없이 로그인"""
        response = self.client.post(
            "/api/accounts/login/", {"email": "test@test.com"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("이메일과 비밀번호", response.data["non_field_errors"][0])

    def test_login_invalid_email_format(self):
        """잘못된 이메일 형식"""
        response = self.client.post(
            "/api/accounts/login/", {"email": "notanemail", "password": "Pass123!"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("이메일 형식", response.data["email"][0])

    def test_login_inactive_user(self):
        """비활성화된 계정 로그인 - Django는 is_active=False 유저를 인증하지 않음"""
        user = User.objects.create_user(
            email="inactive@test.com", nickname="비활성", password="Pass123!"
        )
        user.is_active = False
        user.email_verified = True
        user.save()

        response = self.client.post(
            "/api/accounts/login/",
            {"email": "inactive@test.com", "password": "Pass123!"},
            format="json",
        )
        # is_active=False는 authenticate가 None을 반환하므로 401
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("로그인 실패", response.data["non_field_errors"][0])


class EmailVerificationTestCase(TestCase):
    """이메일 인증 테스트"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="verify@test.com", nickname="인증테스트", password="Pass123!"
        )

    def test_email_verification_success(self):
        """이메일 인증 성공"""
        token = EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=24),
        )

        response = self.client.post(
            "/api/accounts/email-verification/confirm/", {"token": token.token}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("인증이 완료", response.data["message"])

        self.user.refresh_from_db()
        self.assertTrue(self.user.email_verified)
        self.assertIsNotNone(self.user.email_verified_at)

        token.refresh_from_db()
        self.assertTrue(token.is_used)

    def test_email_verification_invalid_token(self):
        """유효하지 않은 토큰"""
        response = self.client.post(
            "/api/accounts/email-verification/confirm/", {"token": "invalid_token"}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("유효하지 않은", response.data["token"][0])

    def test_email_verification_expired_token(self):
        """만료된 토큰"""
        token = EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() - timedelta(hours=1),
        )

        response = self.client.post(
            "/api/accounts/email-verification/confirm/", {"token": token.token}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("만료", response.data["token"][0])

    def test_email_resend_success(self):
        """이메일 재전송 성공"""
        response = self.client.post(
            "/api/accounts/email-verification/resend/", {"email": self.user.email}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("재전송", response.data["message"])

        # 토큰 생성 확인
        self.assertTrue(
            EmailVerificationToken.objects.filter(user=self.user, is_used=False).exists()
        )

    def test_email_resend_already_verified(self):
        """이미 인증된 계정"""
        self.user.email_verified = True
        self.user.save()

        response = self.client.post(
            "/api/accounts/email-verification/resend/", {"email": self.user.email}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("이미 인증", response.data["email"][0])

    def test_email_resend_nonexistent_user(self):
        """존재하지 않는 이메일 - 타이밍 공격 방지"""
        response = self.client.post(
            "/api/accounts/email-verification/resend/",
            {"email": "nonexistent@test.com"},
            format="json",
        )

        # 보안: 동일한 응답
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("전송", response.data["message"])


class EmailVerificationTokenModelTest(BaseTestCase):
    """EmailVerificationToken 모델 테스트"""

    def setUp(self):
        self.user = self.create_user(email="model@test.com", nickname="모델테스트")

    def test_token_str_representation(self):
        """토큰 문자열 표현"""
        token = EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertIn(self.user.email, str(token))

    def test_token_is_expired_property(self):
        """토큰 만료 확인 프로퍼티"""
        # 만료된 토큰
        expired = EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() - timedelta(hours=1),
        )
        self.assertTrue(expired.is_expired)

        # 유효한 토큰
        valid = EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertFalse(valid.is_expired)

    def test_token_is_valid_property(self):
        """토큰 유효성 확인 프로퍼티"""
        # 유효한 토큰
        valid = EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertTrue(valid.is_valid)

        # 사용된 토큰
        valid.is_used = True
        valid.save()
        self.assertFalse(valid.is_valid)

    def test_cleanup_expired(self):
        """만료된 토큰 정리"""
        # 만료된 토큰
        EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() - timedelta(hours=1),
        )

        # 사용된 토큰
        EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
            is_used=True,
        )

        # 유효한 토큰
        valid_token = EmailVerificationToken.objects.create(
            user=self.user,
            token=EmailVerificationToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )

        # 정리 실행
        deleted_count = EmailVerificationToken.objects.delete_expired()

        self.assertEqual(deleted_count, 2)
        self.assertTrue(EmailVerificationToken.objects.filter(id=valid_token.id).exists())


class PasswordChangeTestCase(APITestCase):
    """비밀번호 변경 테스트"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="change@test.com", nickname="변경테스트", password="OldPass123!"
        )
        self.user.email_verified = True
        self.user.save()
        self.client.force_authenticate(user=self.user)

    def test_password_change_success(self):
        """비밀번호 변경 성공"""
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("변경되었습니다", response.data["message"])

        # 새 비밀번호로 인증 확인
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewPass123!"))
        self.assertFalse(self.user.check_password("OldPass123!"))

    def test_password_change_wrong_current_password(self):
        """현재 비밀번호 불일치"""
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "WrongPass123!",
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("현재 비밀번호가 일치하지 않습니다", response.data["current_password"][0])

    def test_password_change_new_password_mismatch(self):
        """새 비밀번호 불일치"""
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password": "NewPass123!",
                "new_password2": "DifferentPass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("비밀번호가 일치하지 않습니다", response.data["new_password"][0])

    def test_password_change_same_as_current(self):
        """현재 비밀번호와 동일한 새 비밀번호"""
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password": "OldPass123!",
                "new_password2": "OldPass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("현재 비밀번호와 다른", response.data["new_password"][0])

    def test_password_change_without_auth(self):
        """인증 없이 비밀번호 변경 시도"""
        self.client.force_authenticate(user=None)

        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_password_change_missing_fields(self):
        """필수 필드 누락"""
        # current_password 누락
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # new_password 누락
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # new_password2 누락
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password": "NewPass123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_change_weak_password(self):
        """새 비밀번호 강도 검증"""
        # 너무 짧음
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password": "Short1!",
                "new_password2": "Short1!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("new_password", response.data)

        # 특수문자 없음
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password": "NewPass123",
                "new_password2": "NewPass123",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("new_password", response.data)


class PasswordChangeE2ETestCase(LiveServerTestCase):
    """비밀번호 변경 E2E 테스트"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="e2e_change@test.com", nickname="E2E변경", password="OldPass123!"
        )
        self.user.email_verified = True
        self.user.save()

    def test_complete_password_change_flow(self):
        """완전한 비밀번호 변경 플로우: 로그인 → 비밀번호 변경 → 재로그인"""
        # 1. 로그인
        response = self.client.post(
            "/api/accounts/login/",
            {"email": "e2e_change@test.com", "password": "OldPass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 2. 비밀번호 변경
        response = self.client.post(
            "/api/accounts/password/change/",
            {
                "current_password": "OldPass123!",
                "new_password": "NewPass123!",
                "new_password2": "NewPass123!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 3. 로그아웃
        self.client.post("/api/accounts/logout/", format="json")

        # 4. 이전 비밀번호로 로그인 실패
        response = self.client.post(
            "/api/accounts/login/",
            {"email": "e2e_change@test.com", "password": "OldPass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # 5. 새 비밀번호로 로그인 성공
        response = self.client.post(
            "/api/accounts/login/",
            {"email": "e2e_change@test.com", "password": "NewPass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AccountDeleteTestCase(APITestCase):
    """회원 탈퇴 테스트"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="delete@test.com", nickname="탈퇴테스트", password="Pass123!"
        )
        self.user.email_verified = True
        self.user.save()
        self.client.force_authenticate(user=self.user)

    def test_account_delete_success(self):
        """회원 탈퇴 예약 성공"""
        response = self.client.post(
            "/api/accounts/account/delete/",
            {"password": "Pass123!"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("예약", response.data["message"])

        # Soft Delete 확인 (is_active = False, scheduled_deletion_at 설정)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertIsNotNone(self.user.scheduled_deletion_at)

    def test_account_delete_wrong_password(self):
        """잘못된 비밀번호로 탈퇴 시도"""
        response = self.client.post(
            "/api/accounts/account/delete/",
            {"password": "WrongPass123!"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("비밀번호가 일치하지 않습니다", response.data["password"][0])

        # 계정 활성 상태 유지
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)

    def test_account_delete_without_auth(self):
        """인증 없이 탈퇴 시도"""
        self.client.force_authenticate(user=None)

        response = self.client.post(
            "/api/accounts/account/delete/",
            {"password": "Pass123!"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_account_delete_missing_password(self):
        """비밀번호 누락"""
        response = self.client.post(
            "/api/accounts/account/delete/",
            {},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class AccountDeleteE2ETestCase(LiveServerTestCase):
    """회원 탈퇴 E2E 테스트"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="e2e_delete@test.com", nickname="E2E탈퇴", password="Pass123!"
        )
        self.user.email_verified = True
        self.user.save()

    def test_account_delete_and_recover_within_grace_period(self):
        """탈퇴 후 유예 기간 내 로그인 시 계정 복구"""
        # 1. 로그인
        response = self.client.post(
            "/api/accounts/login/",
            {"email": "e2e_delete@test.com", "password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 2. 회원 탈퇴 예약
        response = self.client.post(
            "/api/accounts/account/delete/",
            {"password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 3. 로그아웃 상태 확인 (me 접근 불가)
        response = self.client.get("/api/accounts/me/", format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # 4. 유예 기간 내 다시 로그인 → 계정 복구
        response = self.client.post(
            "/api/accounts/login/",
            {"email": "e2e_delete@test.com", "password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 5. 계정이 복구되었는지 확인
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertIsNone(self.user.scheduled_deletion_at)

    def test_account_delete_after_grace_period_expired(self):
        """유예 기간 만료 후 로그인 실패"""
        # 1. 로그인
        response = self.client.post(
            "/api/accounts/login/",
            {"email": "e2e_delete@test.com", "password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 2. 회원 탈퇴 예약
        response = self.client.post(
            "/api/accounts/account/delete/",
            {"password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 3. 유예 기간 만료 시뮬레이션 (과거 시간으로 설정)
        self.user.refresh_from_db()
        self.user.scheduled_deletion_at = timezone.now() - timedelta(hours=1)
        self.user.save(update_fields=["scheduled_deletion_at"])

        # 4. 유예 기간 만료 후 로그인 시도 → 실패
        response = self.client.post(
            "/api/accounts/login/",
            {"email": "e2e_delete@test.com", "password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class EmailCheckTestCase(APITestCase):
    """이메일 중복 체크 테스트"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="existing@test.com", nickname="existing", password="Pass123!"
        )

    def test_email_available(self):
        """사용 가능한 이메일"""
        response = self.client.post(
            "/api/accounts/check-email/",
            {"email": "new@test.com"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["available"])

    def test_email_already_used(self):
        """이미 사용 중인 이메일"""
        response = self.client.post(
            "/api/accounts/check-email/",
            {"email": "existing@test.com"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["available"])
        self.assertIn("이미 사용 중", response.data["message"])

    def test_email_scheduled_deletion(self):
        """탈퇴 예약된 이메일"""
        self.user.is_active = False
        self.user.scheduled_deletion_at = timezone.now() + timedelta(days=1)
        self.user.save()

        response = self.client.post(
            "/api/accounts/check-email/",
            {"email": "existing@test.com"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["available"])
        self.assertIn("탈퇴 예약", response.data["message"])


class NicknameCheckTestCase(APITestCase):
    """닉네임 중복 체크 테스트"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="user@test.com", nickname="existingnick", password="Pass123!"
        )

    def test_nickname_available(self):
        """사용 가능한 닉네임"""
        response = self.client.post(
            "/api/accounts/check-nickname/",
            {"nickname": "newnickname"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["available"])

    def test_nickname_already_used(self):
        """이미 사용 중인 닉네임"""
        response = self.client.post(
            "/api/accounts/check-nickname/",
            {"nickname": "existingnick"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["available"])
        self.assertIn("이미 사용 중", response.data["message"])


class EmailChangeTestCase(APITestCase):
    """이메일 변경 테스트"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="original@test.com", nickname="emailchange", password="Pass123!"
        )
        self.user.email_verified = True
        self.user.save()
        self.client.force_authenticate(user=self.user)

    def test_email_change_request_success(self):
        """이메일 변경 요청 성공"""
        response = self.client.post(
            "/api/accounts/email/change/",
            {"new_email": "new@test.com", "password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("인증 이메일", response.data["message"])

    def test_email_change_wrong_password(self):
        """잘못된 비밀번호로 이메일 변경 요청"""
        response = self.client.post(
            "/api/accounts/email/change/",
            {"new_email": "new@test.com", "password": "WrongPass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)

    def test_email_change_same_email(self):
        """현재 이메일과 동일한 이메일로 변경 시도"""
        response = self.client.post(
            "/api/accounts/email/change/",
            {"new_email": "original@test.com", "password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("new_email", response.data)

    def test_email_change_duplicate_email(self):
        """이미 사용 중인 이메일로 변경 시도"""
        User.objects.create_user(email="taken@test.com", nickname="taken", password="Pass123!")
        response = self.client.post(
            "/api/accounts/email/change/",
            {"new_email": "taken@test.com", "password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("new_email", response.data)

    def test_email_change_without_auth(self):
        """인증 없이 이메일 변경 시도"""
        self.client.force_authenticate(user=None)
        response = self.client.post(
            "/api/accounts/email/change/",
            {"new_email": "new@test.com", "password": "Pass123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class CleanupDeletedAccountsCommandTestCase(TestCase):
    """cleanup_deleted_accounts 관리 명령어 테스트"""

    def test_cleanup_expired_accounts(self):
        """만료된 탈퇴 예약 계정 삭제"""
        from io import StringIO

        from django.core.management import call_command

        # 만료된 탈퇴 예약 계정 생성
        expired_user = User.objects.create_user(
            email="expired@test.com", nickname="expired", password="Pass123!"
        )
        expired_user.is_active = False
        expired_user.scheduled_deletion_at = timezone.now() - timedelta(days=1)
        expired_user.save()

        # 아직 만료되지 않은 탈퇴 예약 계정 생성
        pending_user = User.objects.create_user(
            email="pending@test.com", nickname="pending", password="Pass123!"
        )
        pending_user.is_active = False
        pending_user.scheduled_deletion_at = timezone.now() + timedelta(days=7)
        pending_user.save()

        # 일반 활성 계정 생성
        User.objects.create_user(email="active@test.com", nickname="active", password="Pass123!")

        out = StringIO()
        call_command("cleanup_deleted_accounts", stdout=out)

        # 만료된 계정만 삭제됨
        self.assertFalse(User.objects.filter(email="expired@test.com").exists())
        self.assertTrue(User.objects.filter(email="pending@test.com").exists())
        self.assertTrue(User.objects.filter(email="active@test.com").exists())
        self.assertIn("삭제 완료", out.getvalue())

    def test_cleanup_dry_run(self):
        """dry-run 모드에서는 삭제하지 않음"""
        from io import StringIO

        from django.core.management import call_command

        expired_user = User.objects.create_user(
            email="expired@test.com", nickname="expired", password="Pass123!"
        )
        expired_user.is_active = False
        expired_user.scheduled_deletion_at = timezone.now() - timedelta(days=1)
        expired_user.save()

        out = StringIO()
        call_command("cleanup_deleted_accounts", "--dry-run", stdout=out)

        # 삭제되지 않음
        self.assertTrue(User.objects.filter(email="expired@test.com").exists())
        self.assertIn("DRY-RUN", out.getvalue())

    def test_cleanup_no_accounts_to_delete(self):
        """삭제할 계정이 없는 경우"""
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command("cleanup_deleted_accounts", stdout=out)

        self.assertIn("삭제할 계정이 없습니다", out.getvalue())
