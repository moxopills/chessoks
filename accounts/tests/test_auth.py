import time

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import LiveServerTestCase, TestCase
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory

from accounts.serializers import ProfileUpdateSerializer, UserSignUpSerializer

User = get_user_model()


class BaseTestCase(TestCase):
    """공통 테스트 베이스 클래스"""

    @classmethod
    def setUpTestData(cls):
        """테스트 데이터 공통 설정"""
        cls.valid_signup_data = {
            "email": "test@example.com",
            "nickname": "테스터",
            "bio": "자기소개입니다",
            "password": "TestPass123!",
            "password2": "TestPass123!",
        }

    def create_user(self, email="user@test.com", nickname="유저", password="Pass123!"):
        """테스트 유저 생성 헬퍼"""
        return User.objects.create_user(email=email, nickname=nickname, password=password)


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
        response = self.client.post("/accounts/signup/", signup_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["email"], signup_data["email"])

        # 2. 로그인
        login_data = {"email": "e2e@test.com", "password": "TestPass123!"}
        response = self.client.post("/accounts/login/", login_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("user", response.data)

        # 3. 현재 유저 정보 조회 (로그인 상태)
        response = self.client.get("/accounts/me/", format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], signup_data["email"])
        self.assertEqual(response.data["nickname"], signup_data["nickname"])

        # 4. 로그아웃
        response = self.client.post("/accounts/logout/", format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 5. 로그아웃 후 유저 정보 조회 실패 확인
        response = self.client.get("/accounts/me/", format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_login_failure_lockout_flow(self):
        """로그인 실패 → 잠금 → 해제 플로우 E2E 테스트"""

        # 1. 유저 생성
        User.objects.create_user(
            email="locktest@test.com", nickname="잠금테스트", password="CorrectPass123!"
        )

        wrong_data = {"email": "locktest@test.com", "password": "WrongPass!"}

        # 2. 첫 번째 실패 (남은 시도: 2회)
        response = self.client.post("/accounts/login/", wrong_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("남은 시도: 2회", response.data["error"])

        # 3. 두 번째 실패 (남은 시도: 1회)
        response = self.client.post("/accounts/login/", wrong_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("남은 시도: 1회", response.data["error"])

        # 4. 세 번째 실패 → 잠금
        response = self.client.post("/accounts/login/", wrong_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn("5분 후", response.data["error"])

        # 5. 잠금 상태에서 올바른 비밀번호로도 로그인 불가
        correct_data = {"email": "locktest@test.com", "password": "CorrectPass123!"}
        response = self.client.post("/accounts/login/", correct_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

        # 6. 캐시 수동 삭제 (실제로는 5분 대기)
        cache.delete(f"login_lock:locktest@test.com")
        cache.delete(f"login_fail:locktest@test.com")

        # 7. 잠금 해제 후 올바른 비밀번호로 로그인 성공
        response = self.client.post("/accounts/login/", correct_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_duplicate_signup_prevention(self):
        """중복 회원가입 방지 E2E 테스트"""

        signup_data = {
            "email": "duplicate@test.com",
            "nickname": "중복테스트",
            "password": "TestPass123!",
            "password2": "TestPass123!",
        }

        # 1. 첫 번째 회원가입 성공
        response = self.client.post("/accounts/signup/", signup_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 2. 같은 이메일로 재가입 시도 → 실패
        response = self.client.post("/accounts/signup/", signup_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

        # 3. 다른 이메일, 같은 닉네임으로 재가입 시도 → 실패
        signup_data2 = {
            "email": "another@test.com",
            "nickname": "중복테스트",
            "password": "TestPass123!",
            "password2": "TestPass123!",
        }
        response = self.client.post("/accounts/signup/", signup_data2, format="json")
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
        response = self.client.post("/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 2. 대문자 없음
        data = {**base_data, "password": "testpass123!", "password2": "testpass123!"}
        response = self.client.post("/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 3. 특수문자 없음
        data = {**base_data, "password": "TestPass123", "password2": "TestPass123"}
        response = self.client.post("/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 4. 비밀번호 불일치
        data = {**base_data, "password": "TestPass123!", "password2": "Different!"}
        response = self.client.post("/accounts/signup/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 5. 모든 조건 만족 → 성공
        data = {**base_data, "password": "TestPass123!", "password2": "TestPass123!"}
        response = self.client.post("/accounts/signup/", data, format="json")
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
        self.client.post("/accounts/signup/", signup_data, format="json")

        # 2. 로그인
        login_data = {"email": "session@test.com", "password": "TestPass123!"}
        response = self.client.post("/accounts/login/", login_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 3. 여러 번 /me/ 호출해도 세션 유지
        for _ in range(5):
            response = self.client.get("/accounts/me/", format="json")
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data["email"], "session@test.com")

        # 4. 로그아웃
        self.client.post("/accounts/logout/", format="json")

        # 5. 로그아웃 후 세션 무효화 확인
        response = self.client.get("/accounts/me/", format="json")
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

    def test_password_mismatch(self):
        """비밀번호 불일치 검증"""
        data = self.valid_signup_data.copy()
        data["password"] = "TestPass123!"
        data["password2"] = "DifferentPass123!"
        serializer = UserSignUpSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("일치하지 않습니다", str(serializer.errors["password"][0]))

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
        self.assertEqual(str(user), "테스터 (Rating: 1200)")

    def test_win_rate_with_games(self):
        """게임 기록이 있을 때 승률 계산"""
        user = self.create_user()
        user.games_played = 10
        user.games_won = 7
        user.save()
        self.assertEqual(user.win_rate, 70.0)

    def test_win_rate_no_games(self):
        """게임 기록이 없을 때 승률 0"""
        user = self.create_user()
        self.assertEqual(user.win_rate, 0)

    def test_clean_invalid_rating(self):
        """레이팅 범위 초과 검증"""
        user = self.create_user()
        user.rating = 5000
        with self.assertRaises(ValidationError) as ctx:
            user.clean()
        self.assertIn("레이팅은 0-4000", str(ctx.exception))

    def test_clean_negative_games_played(self):
        """게임 수 음수 검증"""
        user = self.create_user()
        user.games_played = -5
        with self.assertRaises(ValidationError) as ctx:
            user.clean()
        self.assertIn("음수가 될 수 없습니다", str(ctx.exception))

    def test_top_players(self):
        """상위 플레이어 조회"""
        self.create_user(email="p1@test.com", nickname="플1")
        self.create_user(email="p2@test.com", nickname="플2")
        self.create_user(email="p3@test.com", nickname="플3")
        User.objects.filter(email="p1@test.com").update(rating=1500)
        User.objects.filter(email="p2@test.com").update(rating=1800)
        User.objects.filter(email="p3@test.com").update(rating=1300)

        top_players = User.objects.top_players(limit=2)
        self.assertEqual(len(top_players), 2)
        self.assertEqual(top_players[0].rating, 1800)
        self.assertEqual(top_players[1].rating, 1500)

    def test_active_players(self):
        """활성 플레이어 조회"""
        active = self.create_user(email="active@test.com", nickname="활성")
        inactive = self.create_user(email="inactive@test.com", nickname="비활성")
        inactive.is_active = False
        inactive.save()

        players = User.objects.active_players()
        self.assertIn(active, players)
        self.assertNotIn(inactive, players)
