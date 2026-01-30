"""비밀번호/이메일/프로필 관련 서비스"""

import logging
import uuid

from django.contrib.auth import update_session_auth_hash
from django.core.cache import cache
from django.utils import timezone

from rest_framework import status
from rest_framework.exceptions import ValidationError

from apps.accounts.models import AuthToken, User
from apps.accounts.services.base_service import ServiceResult, _ok, _validate_serializer
from apps.accounts.services.session_service import AccountService, PasswordService
from apps.accounts.utils import (
    check_passwords_match,
    create_signup_email_token,
    create_token,
    get_user_or_timing_safe_response,
    mark_signup_token_as_used,
    mark_token_as_used,
    send_email_change_code,
    send_password_reset_code,
    send_signup_verification_email,
    send_verification_email,
    validate_signup_email_code,
    validate_token,
)
from apps.core.gcp.constants import FileType, GCPConstants
from apps.core.gcp.uploader import gcp_uploader
from apps.core.gcp.validators import GCPImageValidator

logger = logging.getLogger(__name__)

# 상수 정의
EMAIL_VERIFICATION_HOURS = 24
PASSWORD_RESET_HOURS = 1
SIGNUP_EMAIL_CACHE_TTL = 600
EMAIL_CHANGE_CODE_TTL = EMAIL_VERIFICATION_HOURS * 60 * 60
PASSWORD_RESET_CODE_TTL = PASSWORD_RESET_HOURS * 60 * 60


def _email_change_code_key(user_id: int, code: str) -> str:
    return f"email_change_code:{user_id}:{code}"


def _password_reset_code_key(code: str) -> str:
    return f"password_reset_code:{code}"


def _check_availability(user: User | None, field_name: str) -> dict:
    result = AccountService.check_availability(user, field_name)
    return {"available": result["available"], "message": result["message"]}


def _validate_avatar_file(file) -> str:
    file_name = file.name
    GCPImageValidator.validate_file_name(file_name)
    ext = file_name.rsplit(".", 1)[-1].lower()
    GCPImageValidator.validate_extension(file_name, ext)
    GCPImageValidator.validate_mime_type(ext, file.content_type)
    GCPImageValidator.validate_file_size(file.size)
    return ext


def _extract_old_avatar_key(user: User) -> str | None:
    if not user.avatar_url:
        return None
    return gcp_uploader.extract_key_from_url(user.avatar_url)


def _upload_new_avatar(file, ext: str) -> str:
    prefix = GCPConstants.PATH_MAPPING[FileType.USER_AVATAR]
    key = f"{prefix}/{uuid.uuid4()}.{ext}"

    gcp_uploader.upload_fileobj(
        file.file,
        key,
        content_type=file.content_type,
    )

    return f"{gcp_uploader.get_base_url()}{key}"


class UserProfileService:
    """비밀번호/이메일/프로필 흐름 서비스"""

    @staticmethod
    def _validate_availability(email: str, nickname: str) -> None:
        """이메일/닉네임 가용성 검증"""
        email_user = User.objects.filter(email=email).first()
        result = AccountService.check_availability(email_user, "이메일")
        if not result["available"]:
            raise ValidationError({"email": [result["message"]]})

        nickname_user = User.objects.filter(nickname=nickname).first()
        result = AccountService.check_availability(nickname_user, "닉네임")
        if not result["available"]:
            raise ValidationError({"nickname": [result["message"]]})

    @staticmethod
    def signup(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        check_passwords_match(
            serializer.validated_data["password"],
            serializer.validated_data["password2"],
        )

        email = serializer.validated_data["email"]
        cache_key = f"signup_email_verified:{email}"
        if not cache.get(cache_key):
            raise ValidationError({"email": ["이메일 인증을 먼저 완료해주세요."]})

        UserProfileService._validate_availability(
            email,
            serializer.validated_data["nickname"],
        )

        user = serializer.save()
        AccountService.verify_email(user)
        cache.delete(cache_key)

        return _ok(
            {
                "message": "회원가입이 완료되었습니다.",
                "email": user.email,
            },
            status.HTTP_201_CREATED,
        )

    @staticmethod
    def signup_email_request(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        email = serializer.validated_data["email"]
        email_user = User.objects.filter(email=email).first()
        result = AccountService.check_availability(email_user, "이메일")
        if not result["available"]:
            raise ValidationError({"email": [result["message"]]})

        token, code = create_signup_email_token(email=email, expiry_hours=EMAIL_VERIFICATION_HOURS)
        send_signup_verification_email(email, code)

        return _ok(
            {
                "message": "인증 이메일을 전송했습니다.",
                "email": email,
            },
            status.HTTP_200_OK,
        )

    @staticmethod
    def signup_email_confirm(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        email = serializer.validated_data["email"]
        code = serializer.validated_data["code"]
        token, error_response = validate_signup_email_code(
            email,
            code,
            error_messages={
                "not_found": "인증 요청을 먼저 진행해주세요.",
                "invalid": "만료되었거나 이미 사용된 인증입니다.",
                "mismatch": "인증 코드가 일치하지 않습니다.",
            },
        )
        if error_response:
            raise ValidationError(error_response.data)

        mark_signup_token_as_used(token)
        cache.set(f"signup_email_verified:{email}", True, timeout=SIGNUP_EMAIL_CACHE_TTL)
        return _ok(
            {"message": "이메일 인증이 완료되었습니다.", "email": email},
            status.HTTP_200_OK,
        )

    @staticmethod
    def password_reset_request(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        email = serializer.validated_data["email"]
        success_message = "비밀번호 재설정 인증번호를 이메일로 전송했습니다."

        user, error_response = get_user_or_timing_safe_response(
            email=email, success_message=success_message, is_active_only=True
        )
        if error_response:
            return _ok(error_response.data, error_response.status_code)

        token = create_token(
            token_type=AuthToken.TokenType.PASSWORD_RESET,
            user=user,
            expiry_hours=PASSWORD_RESET_HOURS,
        )
        code = f"{uuid.uuid4().int % 1_000_000:06d}"
        cache.set(_password_reset_code_key(code), token.token, timeout=PASSWORD_RESET_CODE_TTL)
        send_password_reset_code(user.email, code)

        return _ok({"message": success_message}, status.HTTP_200_OK)

    @staticmethod
    def password_reset_confirm(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        check_passwords_match(
            serializer.validated_data["new_password"],
            serializer.validated_data["new_password2"],
            field_name="new_password",
        )

        code = serializer.validated_data["code"]
        token_str = cache.get(_password_reset_code_key(code))
        if not token_str:
            raise ValidationError({"code": ["유효하지 않은 인증번호입니다."]})
        new_password = serializer.validated_data["new_password"]

        token, error_response = validate_token(
            token_str, token_type=AuthToken.TokenType.PASSWORD_RESET
        )
        if error_response:
            raise ValidationError(error_response.data)

        PasswordService.change_password(token.user, new_password)
        mark_token_as_used(token)
        cache.delete(_password_reset_code_key(code))

        return _ok({"message": "비밀번호가 재설정되었습니다."}, status.HTTP_200_OK)

    @staticmethod
    def password_change(serializer, user: User, request=None) -> ServiceResult:
        _validate_serializer(serializer)

        current_password = serializer.validated_data["current_password"]
        new_password = serializer.validated_data["new_password"]
        new_password2 = serializer.validated_data["new_password2"]

        if not PasswordService.verify_current_password(user, current_password):
            raise ValidationError({"current_password": ["현재 비밀번호가 일치하지 않습니다."]})

        check_passwords_match(
            new_password,
            new_password2,
            field_name="new_password",
        )

        if PasswordService.is_same_as_current(user, new_password):
            raise ValidationError(
                {"new_password": ["현재 비밀번호와 다른 비밀번호를 입력해주세요."]}
            )

        PasswordService.change_password(user, new_password)

        # 현재 세션 유지, 다른 세션 무효화
        if request:
            update_session_auth_hash(request, user)

        return _ok({"message": "비밀번호가 변경되었습니다."}, status.HTTP_200_OK)

    @staticmethod
    def email_verification_confirm(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        token_str = serializer.validated_data["token"]
        token, error_response = validate_token(
            token_str,
            token_type=AuthToken.TokenType.EMAIL_VERIFICATION,
            error_messages={
                "not_found": "유효하지 않은 인증 링크입니다.",
                "invalid": "만료되었거나 이미 사용된 인증 링크입니다.",
            },
        )
        if error_response:
            raise ValidationError(error_response.data)

        AccountService.verify_email(token.user)
        mark_token_as_used(token)

        return _ok(
            {"message": "이메일 인증이 완료되었습니다. 이제 로그인할 수 있습니다."},
            status.HTTP_200_OK,
        )

    @staticmethod
    def email_verification_resend(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        email = serializer.validated_data["email"]
        success_message = "인증 이메일을 전송했습니다."
        user, error_response = get_user_or_timing_safe_response(
            email=email, success_message=success_message, is_active_only=True
        )
        if error_response:
            return _ok(error_response.data, error_response.status_code)

        if user.email_verified:
            raise ValidationError({"email": ["이미 인증된 계정입니다."]})

        token = create_token(
            token_type=AuthToken.TokenType.EMAIL_VERIFICATION,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
        )
        send_verification_email(user.email, token.token)

        return _ok({"message": "인증 이메일을 재전송했습니다."}, status.HTTP_200_OK)

    @staticmethod
    def avatar_update(user: User, file) -> ServiceResult:
        if not file:
            raise ValidationError({"avatar": ["아바타 파일이 필요합니다."]})

        ext = _validate_avatar_file(file)
        old_avatar_key = _extract_old_avatar_key(user)
        new_avatar_url = _upload_new_avatar(file, ext)

        user.avatar_url = new_avatar_url
        user.save(update_fields=["avatar_url"])

        if old_avatar_key:
            try:
                gcp_uploader.delete_file(old_avatar_key)
            except Exception as e:
                logger.warning(f"이전 아바타 삭제 실패: {old_avatar_key}, error: {e}")

        return _ok(
            {"message": "아바타가 성공적으로 업데이트되었습니다.", "avatar_url": new_avatar_url},
            status.HTTP_200_OK,
        )

    @staticmethod
    def avatar_delete(user: User) -> ServiceResult:
        if not user.avatar_url:
            raise ValidationError({"avatar": ["삭제할 아바타가 없습니다."]})

        old_avatar_key = _extract_old_avatar_key(user)
        if old_avatar_key:
            try:
                gcp_uploader.delete_file(old_avatar_key)
            except Exception as e:
                logger.warning(f"아바타 삭제 실패: {old_avatar_key}, error: {e}")

        user.avatar_url = None
        user.save(update_fields=["avatar_url"])

        return _ok({"message": "아바타가 삭제되었습니다."}, status.HTTP_200_OK)

    @staticmethod
    def email_check(serializer) -> ServiceResult:
        _validate_serializer(serializer)
        user = User.objects.filter(email=serializer.validated_data["email"]).first()
        return _ok(_check_availability(user, "이메일"), status.HTTP_200_OK)

    @staticmethod
    def nickname_check(serializer) -> ServiceResult:
        _validate_serializer(serializer)
        user = User.objects.filter(nickname=serializer.validated_data["nickname"]).first()
        return _ok(_check_availability(user, "닉네임"), status.HTTP_200_OK)

    @staticmethod
    def profile_update(serializer, user: User) -> ServiceResult:
        _validate_serializer(serializer)

        new_nickname = serializer.validated_data.get("nickname")
        if new_nickname and new_nickname != user.nickname:
            if user.nickname_changed_at:
                elapsed = timezone.now() - user.nickname_changed_at
                if elapsed.total_seconds() < 24 * 60 * 60:
                    raise ValidationError(
                        {"nickname": ["닉네임은 24시간에 1회만 변경할 수 있습니다."]}
                    )
            existing = User.objects.filter(nickname=new_nickname).exclude(pk=user.pk).first()
            result = AccountService.check_availability(existing, "닉네임")
            if not result["available"]:
                raise ValidationError({"nickname": [result["message"]]})

        old_nickname = user.nickname
        serializer.save()
        if new_nickname and new_nickname != old_nickname:
            user.nickname_changed_at = timezone.now()
            user.save(update_fields=["nickname_changed_at"])
        return _ok({"message": "프로필이 업데이트되었습니다."}, status.HTTP_200_OK)

    @staticmethod
    def email_change_request(serializer, user: User) -> ServiceResult:
        _validate_serializer(serializer)

        new_email = serializer.validated_data["new_email"]
        password = serializer.validated_data["password"]

        if not PasswordService.verify_current_password(user, password):
            raise ValidationError({"password": ["비밀번호가 일치하지 않습니다."]})

        if user.email == new_email:
            raise ValidationError({"new_email": ["현재 이메일과 동일합니다."]})

        if User.objects.filter(email=new_email).exists():
            raise ValidationError({"new_email": ["이미 사용 중인 이메일입니다."]})

        token = create_token(
            token_type=AuthToken.TokenType.EMAIL_VERIFICATION,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
            new_email=new_email,
        )
        code = f"{uuid.uuid4().int % 1_000_000:06d}"
        cache.set(_email_change_code_key(user.id, code), token.token, timeout=EMAIL_CHANGE_CODE_TTL)
        send_email_change_code(new_email, code)

        return _ok({"message": f"인증번호를 {new_email}로 전송했습니다."}, status.HTTP_200_OK)

    @staticmethod
    def email_change_confirm(serializer, user: User) -> ServiceResult:
        _validate_serializer(serializer)

        code = serializer.validated_data["code"]
        token_str = cache.get(_email_change_code_key(user.id, code))
        if not token_str:
            raise ValidationError({"code": ["유효하지 않은 인증번호입니다."]})
        token, error_response = validate_token(
            token_str,
            token_type=AuthToken.TokenType.EMAIL_VERIFICATION,
            error_messages={
                "not_found": "유효하지 않은 인증번호입니다.",
                "invalid": "만료되었거나 이미 사용된 인증번호입니다.",
            },
        )
        if error_response:
            raise ValidationError(error_response.data)

        if token.user_id != user.id:
            raise ValidationError({"code": ["본인의 인증번호가 아닙니다."]})

        new_email = token.new_email
        if not new_email:
            raise ValidationError(
                {"code": ["이메일 변경 요청이 만료되었습니다. 다시 시도해주세요."]}
            )

        if User.objects.filter(email=new_email).exclude(pk=user.pk).exists():
            raise ValidationError({"new_email": ["이미 사용 중인 이메일입니다."]})

        user.email = new_email
        user.save(update_fields=["email"])

        mark_token_as_used(token)
        cache.delete(_email_change_code_key(user.id, code))
        return _ok({"message": f"이메일이 {new_email}로 변경되었습니다."}, status.HTTP_200_OK)
