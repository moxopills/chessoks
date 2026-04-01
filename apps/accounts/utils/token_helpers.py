"""토큰 생성 및 검증 헬퍼 함수"""

import hashlib
import hmac
import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from rest_framework import status
from rest_framework.response import Response

from apps.accounts.models import AuthToken, SignupEmailToken
from apps.accounts.services.token_service import TokenService


def create_token(
    token_type: str,
    user,
    expiry_hours: int,
    invalidate_existing: bool = True,
    new_email: str | None = None,
) -> AuthToken:
    """토큰 생성 및 기존 토큰 무효화

    Args:
        token_type: 토큰 타입 (AuthToken.TokenType.EMAIL_VERIFICATION 등)
        user: 연결된 사용자
        expiry_hours: 토큰 만료 시간 (시간 단위)
        invalidate_existing: 기존 미사용 토큰 무효화 여부
        new_email: 이메일 변경 요청 시 새 이메일

    Returns:
        생성된 토큰 인스턴스
    """
    if invalidate_existing:
        AuthToken.objects.filter(user=user, token_type=token_type, is_used=False).update(
            is_used=True
        )

    token = AuthToken.objects.create(
        user=user,
        token_type=token_type,
        token=TokenService.generate_token(),
        expires_at=timezone.now() + timedelta(hours=expiry_hours),
        new_email=new_email,
    )

    return token


def validate_token(
    token_str: str,
    token_type: str | None = None,
    error_messages: dict[str, str] | None = None,
) -> tuple[AuthToken | None, Response | None]:
    """토큰 검증 및 에러 응답 반환

    Args:
        token_str: 토큰 문자열
        token_type: 특정 토큰 타입으로 필터링 (None이면 전체)
        error_messages: 커스텀 에러 메시지 dict
            - "not_found": 토큰이 존재하지 않을 때
            - "invalid": 토큰이 만료/사용됨일 때

    Returns:
        (token_instance, error_response) 튜플
        - 성공 시: (token, None)
        - 실패 시: (None, Response)
    """
    default_messages = {
        "not_found": "유효하지 않은 토큰입니다.",
        "invalid": "만료되었거나 이미 사용된 토큰입니다.",
    }

    if error_messages:
        default_messages.update(error_messages)

    filters = {"token": token_str}
    if token_type:
        filters["token_type"] = token_type

    try:
        token = AuthToken.objects.select_related("user").get(**filters)
    except AuthToken.DoesNotExist:
        return None, Response(
            {"code": [default_messages["not_found"]]},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not TokenService.is_valid(token):
        return None, Response(
            {"code": [default_messages["invalid"]]},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return token, None


def mark_token_as_used(token: AuthToken) -> None:
    """토큰을 사용 완료 상태로 표시

    Args:
        token: 토큰 인스턴스
    """
    token.is_used = True
    token.used_at = timezone.now()
    token.save(update_fields=["is_used", "used_at"])


def create_signup_email_token(
    email: str,
    expiry_hours: int,
    invalidate_existing: bool = True,
) -> tuple[SignupEmailToken, str]:
    """회원가입 이메일 인증 토큰 생성 (코드 반환)

    Args:
        email: 인증 대상 이메일
        expiry_hours: 토큰 만료 시간 (시간 단위)
        invalidate_existing: 기존 미사용 토큰 무효화 여부

    Returns:
        (토큰 인스턴스, 코드 문자열)
    """
    if invalidate_existing:
        TokenService.invalidate_existing_signup_tokens(email=email)

    code = f"{secrets.randbelow(1000000):06d}"
    token = SignupEmailToken.objects.create(
        email=email,
        token=TokenService.generate_token(),
        code_hash=_hash_signup_code(email, code),
        expires_at=timezone.now() + timedelta(hours=expiry_hours),
    )

    return token, code


def validate_signup_email_code(
    email: str,
    code: str,
    error_messages: dict[str, str] | None = None,
    max_attempts: int = 5,
) -> tuple[SignupEmailToken | None, Response | None]:
    """회원가입 이메일 코드 검증

    Args:
        email: 인증 이메일
        code: 인증 코드
        error_messages: 커스텀 에러 메시지 dict
            - "not_found": 인증 요청이 없을 때
            - "invalid": 토큰이 만료/사용됨일 때
            - "mismatch": 코드가 일치하지 않을 때

    Returns:
        (token_instance, error_response) 튜플
        - 성공 시: (token, None)
        - 실패 시: (None, Response)
    """
    default_messages = {
        "not_found": "인증 요청을 먼저 진행해주세요.",
        "invalid": "만료되었거나 이미 사용된 인증입니다.",
        "mismatch": "인증 코드가 일치하지 않습니다.",
    }

    if error_messages:
        default_messages.update(error_messages)

    token = (
        SignupEmailToken.objects.filter(email=email, is_used=False).order_by("-created_at").first()
    )
    if token is None:
        return None, Response(
            {"code": [default_messages["not_found"]]},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not TokenService.is_valid(token):
        return None, Response(
            {"code": [default_messages["invalid"]]},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not _verify_signup_code(email, code, token.code_hash):
        token.attempts += 1
        if token.attempts >= max_attempts:
            token.is_used = True
            token.used_at = timezone.now()
        token.save(update_fields=["attempts", "is_used", "used_at"])
        return None, Response(
            {"code": [default_messages["mismatch"]]},
            status=status.HTTP_400_BAD_REQUEST,
        )

    return token, None


def mark_signup_token_as_used(token: SignupEmailToken) -> None:
    """회원가입 이메일 토큰을 사용 완료 상태로 표시"""
    token.is_used = True
    token.used_at = timezone.now()
    token.save(update_fields=["is_used", "used_at"])


def _hash_signup_code(email: str, code: str) -> str:
    key = settings.SECRET_KEY.encode()
    msg = f"{email}:{code}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _verify_signup_code(email: str, code: str, code_hash: str) -> bool:
    expected = _hash_signup_code(email, code)
    return hmac.compare_digest(expected, code_hash)


def hash_signup_code_for_test(email: str, code: str) -> str:
    """테스트 전용: 코드 해시 생성"""
    return _hash_signup_code(email, code)


def get_user_or_timing_safe_response(
    email: str,
    success_message: str,
    is_active_only: bool = True,
) -> tuple:
    """이메일로 유저 조회 (타이밍 공격 방지)

    Args:
        email: 조회할 이메일
        success_message: 성공 응답 메시지
        is_active_only: 활성 유저만 조회할지 여부

    Returns:
        (user, response) 튜플
        - 유저 존재: (user, None)
        - 유저 없음: (None, Response) - 보안을 위해 성공 응답 반환
    """
    from apps.accounts.models import User

    filters = {"email": email}
    if is_active_only:
        filters["is_active"] = True

    try:
        user = User.objects.get(**filters)
        return user, None
    except User.DoesNotExist:
        # 보안: 존재하지 않는 이메일도 동일하게 처리 (타이밍 공격 방지)
        return None, Response(
            {"message": success_message},
            status=status.HTTP_200_OK,
        )
