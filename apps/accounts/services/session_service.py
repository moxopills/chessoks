"""로그인/세션/탈퇴 관련 서비스"""

from datetime import timedelta

from django.contrib.auth import authenticate, login, logout
from django.core.cache import cache
from django.utils import timezone

from rest_framework import status
from rest_framework.exceptions import (
    AuthenticationFailed,
    PermissionDenied,
    Throttled,
    ValidationError,
)

from apps.accounts.models import User
from apps.accounts.services.base_service import ServiceResult, _ok, _validate_serializer

# 상수 정의
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_DURATION = 300  # 5분
ACCOUNT_DELETION_GRACE_DAYS = 1  # 탈퇴 유예 기간 (일)


class AuthService:
    """인증 관련 비즈니스 로직"""

    @staticmethod
    def check_lockout(email: str) -> bool:
        """잠금 상태 확인"""
        return bool(cache.get(f"login_lock:{email}"))

    @staticmethod
    def try_recover_account(email: str, password: str) -> bool:
        """탈퇴 예약 계정 복구 시도

        Returns:
            True: 복구 성공, False: 복구 불가 또는 해당 없음
        """
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return False

        if (
            not user.is_active
            and user.scheduled_deletion_at
            and user.scheduled_deletion_at > timezone.now()
            and user.check_password(password)
        ):
            user.is_active = True
            user.scheduled_deletion_at = None
            user.save(update_fields=["is_active", "scheduled_deletion_at"])
            return True

        return False

    @staticmethod
    def handle_failed_login(email: str) -> tuple[int, str]:
        """로그인 실패 처리

        Returns:
            (남은 시도 횟수, 에러 메시지) - 잠금 시 남은 시도 = 0
        """
        attempts_key = f"login_fail:{email}"
        attempts = cache.get(attempts_key, 0) + 1

        if attempts >= MAX_LOGIN_ATTEMPTS:
            cache.set(f"login_lock:{email}", 1, LOGIN_LOCKOUT_DURATION)
            cache.delete(attempts_key)
            return 0, "로그인 5회 실패. 5분 후 다시 시도해주세요."

        cache.set(attempts_key, attempts, LOGIN_LOCKOUT_DURATION)
        remaining = MAX_LOGIN_ATTEMPTS - attempts
        return remaining, f"로그인 실패. 남은 시도: {remaining}회"

    @staticmethod
    def handle_successful_login(request, user: User) -> User:
        """로그인 성공 처리 - 세션 생성 및 last_login 업데이트

        Returns:
            stats가 로드된 User 객체
        """
        email = user.email
        cache.delete(f"login_fail:{email}")
        login(request, user)

        # last_login 업데이트 및 stats 로드를 한 번의 쿼리로 처리
        User.objects.filter(pk=user.pk).update(last_login=timezone.now())

        return User.objects.select_related("stats").get(pk=user.pk)


class AccountService:
    """계정 관련 비즈니스 로직"""

    @staticmethod
    def schedule_deletion(user: User) -> None:
        """회원 탈퇴 예약"""
        user.is_active = False
        user.scheduled_deletion_at = timezone.now() + timedelta(days=ACCOUNT_DELETION_GRACE_DAYS)
        user.save(update_fields=["is_active", "scheduled_deletion_at"])

    @staticmethod
    def logout_user(request) -> None:
        """로그아웃 처리"""
        logout(request)

    @staticmethod
    def delete_if_expired(user: User) -> bool:
        """유예 기간 만료된 탈퇴 예약 계정이면 삭제

        Returns:
            True: 삭제됨, False: 삭제 대상 아님
        """
        if (
            not user.is_active
            and user.scheduled_deletion_at
            and user.scheduled_deletion_at <= timezone.now()
        ):
            user.delete()
            return True
        return False

    @staticmethod
    def is_in_deletion_grace_period(user: User) -> bool:
        """유예 기간 내 탈퇴 예약 상태인지 확인"""
        return (
            not user.is_active
            and user.scheduled_deletion_at is not None
            and user.scheduled_deletion_at > timezone.now()
        )

    @staticmethod
    def verify_email(user: User) -> None:
        """이메일 인증 완료 처리"""
        user.email_verified = True
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified", "email_verified_at"])


class PasswordService:
    """비밀번호 관련 비즈니스 로직"""

    @staticmethod
    def verify_current_password(user: User, password: str) -> bool:
        """현재 비밀번호 확인"""
        return user.check_password(password)

    @staticmethod
    def change_password(user: User, new_password: str) -> None:
        """비밀번호 변경"""
        user.set_password(new_password)
        user.save(update_fields=["password"])

    @staticmethod
    def is_same_as_current(user: User, new_password: str) -> bool:
        """새 비밀번호가 현재 비밀번호와 동일한지 확인"""
        return user.check_password(new_password)


class AccountSessionService:
    """로그인/세션/탈퇴 흐름 서비스"""

    @staticmethod
    def login(request, email: str, password: str) -> ServiceResult:
        if not email or not password:
            raise ValidationError({"non_field_errors": ["이메일과 비밀번호를 입력해주세요."]})

        email = User.objects.normalize_email(email.strip())

        if "@" not in email:
            raise ValidationError({"email": ["올바른 이메일 형식이 아닙니다."]})

        if AuthService.check_lockout(email):
            raise Throttled(detail="로그인 시도 횟수 초과. 5분 후 다시 시도해주세요.")

        AuthService.try_recover_account(email, password)

        user = authenticate(request, username=email, password=password)
        if not user:
            remaining, error_msg = AuthService.handle_failed_login(email)
            if remaining == 0:
                raise Throttled(detail=error_msg)
            raise AuthenticationFailed(detail=error_msg)

        if not user.is_active:
            raise PermissionDenied(detail="비활성화된 계정입니다.")

        if not user.email_verified:
            raise PermissionDenied(
                detail="이메일 인증이 필요합니다. 가입 시 받은 이메일의 인증 링크를 확인해주세요."
            )

        user_with_stats = AuthService.handle_successful_login(request, user)
        return _ok(
            payload={"user": user_with_stats, "message": "로그인 성공"},
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def logout(request) -> ServiceResult:
        AccountService.logout_user(request)
        return _ok(
            data={"message": "로그아웃 되었습니다."},
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def account_delete(serializer, user: User, request) -> ServiceResult:
        _validate_serializer(serializer)

        password = serializer.validated_data["password"]
        if not PasswordService.verify_current_password(user, password):
            raise ValidationError({"password": ["비밀번호가 일치하지 않습니다."]})

        AccountService.schedule_deletion(user)
        AccountService.logout_user(request)

        return _ok(
            data={"message": "회원 탈퇴가 예약되었습니다. 1일 내 로그인하면 취소됩니다."},
            status_code=status.HTTP_200_OK,
        )
