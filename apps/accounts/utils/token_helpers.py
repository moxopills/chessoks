"""토큰 생성 및 검증 헬퍼 함수"""

from datetime import timedelta

from django.utils import timezone

from rest_framework import status
from rest_framework.response import Response

from apps.accounts.models import AuthToken


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
        token=AuthToken.generate_token(),
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
            {"token": [default_messages["not_found"]]},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not token.is_valid:
        return None, Response(
            {"token": [default_messages["invalid"]]},
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
