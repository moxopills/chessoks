"""비밀번호/이메일/프로필 관련 서비스"""

import uuid

from rest_framework import status
from rest_framework.exceptions import ValidationError

from apps.accounts.models import EmailVerificationToken, PasswordResetToken, User
from apps.accounts.services.base_service import ServiceResult, _ok, _validate_serializer
from apps.accounts.services.session_service import AccountService, PasswordService
from apps.accounts.utils import (
    check_passwords_match,
    create_token,
    get_user_or_timing_safe_response,
    mark_token_as_used,
    send_password_reset_email,
    send_verification_email,
    validate_token,
)
from apps.core.S3.constants import FileType, S3Constants
from apps.core.S3.uploader import s3_uploader
from apps.core.S3.validators import S3ImageValidator

# 상수 정의
EMAIL_VERIFICATION_HOURS = 24
PASSWORD_RESET_HOURS = 1


def _check_availability(user: User | None, field_name: str) -> dict:
    available_msg = f"사용 가능한 {field_name}입니다."
    used_msg = f"이미 사용 중인 {field_name}입니다."
    scheduled_msg = (
        "탈퇴 예약된 계정입니다. 기존 비밀번호로 로그인하면 복구됩니다."
        if field_name == "이메일"
        else f"탈퇴 예약된 계정의 {field_name}입니다. 잠시 후 다시 시도해주세요."
    )

    if not user:
        return {"available": True, "message": available_msg}

    if AccountService.delete_if_expired(user):
        return {"available": True, "message": available_msg}

    if AccountService.is_in_deletion_grace_period(user):
        return {"available": False, "message": scheduled_msg}

    return {"available": False, "message": used_msg}


def _validate_avatar_file(file) -> str:
    file_name = file.name
    S3ImageValidator.validate_file_name(file_name)
    ext = file_name.rsplit(".", 1)[-1].lower()
    S3ImageValidator.validate_extension(file_name, ext)
    S3ImageValidator.validate_mime_type(ext, file.content_type)
    S3ImageValidator.validate_file_size(file.size)
    return ext


def _extract_old_avatar_key(user: User) -> str | None:
    if not user.avatar_url:
        return None
    return s3_uploader.extract_key_from_url(user.avatar_url)


def _upload_new_avatar(file, ext: str) -> str:
    prefix = S3Constants.PATH_MAPPING[FileType.USER_AVATAR]
    key = f"{prefix}/{uuid.uuid4()}.{ext}"

    s3_uploader.get_s3_client().upload_fileobj(
        file.file,
        s3_uploader.get_bucket_name(),
        key,
        ExtraArgs={"ContentType": file.content_type},
    )

    return f"{s3_uploader.get_s3_base_url()}{key}"


class UserProfileService:
    """비밀번호/이메일/프로필 흐름 서비스"""

    @staticmethod
    def signup(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        check_passwords_match(
            serializer.validated_data["password"],
            serializer.validated_data["password2"],
        )

        user = serializer.save()
        token = create_token(
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
            invalidate_existing=True,
        )
        send_verification_email(user.email, token.token)

        return _ok(
            data={
                "message": "회원가입 성공! 이메일로 전송된 인증 링크를 확인해주세요.",
                "email": user.email,
            },
            status_code=status.HTTP_201_CREATED,
        )

    @staticmethod
    def password_reset_request(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        email = serializer.validated_data["email"]
        success_message = "비밀번호 재설정 링크를 이메일로 전송했습니다."

        user, error_response = get_user_or_timing_safe_response(
            email=email, success_message=success_message, is_active_only=True
        )
        if error_response:
            return _ok(data=error_response.data, status_code=error_response.status_code)

        token = create_token(
            token_model=PasswordResetToken,
            user=user,
            expiry_hours=PASSWORD_RESET_HOURS,
            invalidate_existing=True,
        )
        send_password_reset_email(user.email, token.token)

        return _ok(
            data={"message": success_message},
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def password_reset_confirm(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        check_passwords_match(
            serializer.validated_data["new_password"],
            serializer.validated_data["new_password2"],
            field_name="new_password",
        )

        token_str = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        token, error_response = validate_token(PasswordResetToken, token_str)
        if error_response:
            raise ValidationError(error_response.data)

        PasswordService.change_password(token.user, new_password)
        mark_token_as_used(token)

        return _ok(
            data={"message": "비밀번호가 재설정되었습니다."},
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def password_change(serializer, user: User) -> ServiceResult:
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
        return _ok(
            data={"message": "비밀번호가 변경되었습니다."},
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def email_verification_confirm(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        token_str = serializer.validated_data["token"]
        token, error_response = validate_token(
            token_model=EmailVerificationToken,
            token_str=token_str,
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
            data={"message": "이메일 인증이 완료되었습니다. 이제 로그인할 수 있습니다."},
            status_code=status.HTTP_200_OK,
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
            return _ok(data=error_response.data, status_code=error_response.status_code)

        if user.email_verified:
            raise ValidationError({"email": ["이미 인증된 계정입니다."]})

        token = create_token(
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
            invalidate_existing=True,
        )
        send_verification_email(user.email, token.token)

        return _ok(
            data={"message": "인증 이메일을 재전송했습니다."},
            status_code=status.HTTP_200_OK,
        )

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
                s3_uploader.delete_file(old_avatar_key)
            except Exception:
                pass

        return _ok(
            data={
                "message": "아바타가 성공적으로 업데이트되었습니다.",
                "avatar_url": new_avatar_url,
            },
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def avatar_delete(user: User) -> ServiceResult:
        if not user.avatar_url:
            raise ValidationError({"avatar": ["삭제할 아바타가 없습니다."]})

        old_avatar_key = _extract_old_avatar_key(user)
        if old_avatar_key:
            try:
                s3_uploader.delete_file(old_avatar_key)
            except Exception:
                pass

        user.avatar_url = None
        user.save(update_fields=["avatar_url"])

        return _ok(
            data={"message": "아바타가 삭제되었습니다."},
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def email_check(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        user = User.objects.filter(email=serializer.validated_data["email"]).first()
        return _ok(
            data=_check_availability(user, "이메일"),
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def nickname_check(serializer) -> ServiceResult:
        _validate_serializer(serializer)

        user = User.objects.filter(nickname=serializer.validated_data["nickname"]).first()
        return _ok(
            data=_check_availability(user, "닉네임"),
            status_code=status.HTTP_200_OK,
        )

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
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
            invalidate_existing=True,
        )
        token.new_email = new_email
        token.save(update_fields=["new_email"])
        send_verification_email(new_email, token.token)

        return _ok(
            data={"message": f"인증 이메일을 {new_email}로 전송했습니다."},
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def email_change_confirm(serializer, user: User) -> ServiceResult:
        _validate_serializer(serializer)

        token_str = serializer.validated_data["token"]
        token, error_response = validate_token(
            token_model=EmailVerificationToken,
            token_str=token_str,
            error_messages={
                "not_found": "유효하지 않은 인증 토큰입니다.",
                "invalid": "만료되었거나 이미 사용된 토큰입니다.",
            },
        )
        if error_response:
            raise ValidationError(error_response.data)

        if token.user_id != user.id:
            raise ValidationError({"token": ["본인의 인증 토큰이 아닙니다."]})

        new_email = token.new_email
        if not new_email:
            raise ValidationError(
                {"token": ["이메일 변경 요청이 만료되었습니다. 다시 시도해주세요."]}
            )

        if User.objects.filter(email=new_email).exclude(pk=user.pk).exists():
            raise ValidationError({"new_email": ["이미 사용 중인 이메일입니다."]})

        user.email = new_email
        user.save(update_fields=["email"])

        mark_token_as_used(token)
        return _ok(
            data={"message": f"이메일이 {new_email}로 변경되었습니다."},
            status_code=status.HTTP_200_OK,
        )
