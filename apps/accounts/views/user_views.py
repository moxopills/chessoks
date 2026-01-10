"""사용자 인증 및 프로필 관련 View"""

import uuid
from typing import Any

from django.contrib.auth import authenticate
from django.core.cache import cache

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.generics import RetrieveAPIView, UpdateAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.accounts.models import EmailVerificationToken, PasswordResetToken, User
from apps.accounts.serializers import (
    AccountDeleteSerializer,
    EmailChangeConfirmSerializer,
    EmailChangeRequestSerializer,
    EmailCheckSerializer,
    EmailVerificationResendSerializer,
    EmailVerificationSerializer,
    LoginRequestSerializer,
    LoginResponseSerializer,
    NicknameCheckSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfileUpdateSerializer,
    UserSerializer,
    UserSignUpSerializer,
)
from apps.accounts.services import AccountService, AuthService, PasswordService
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


class CurrentUserMixin:
    """현재 로그인한 유저를 stats와 함께 조회하는 Mixin"""

    def get_object(self):
        return User.objects.select_related("stats").get(pk=self.request.user.pk)


def check_availability(user: User | None, field_name: str) -> dict:
    """이메일/닉네임 사용 가능 여부 확인"""
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


class LoginView(APIView):
    """로그인 - 3번 실패 시 5분 잠금"""

    permission_classes = [AllowAny]

    @extend_schema(
        request=LoginRequestSerializer,
        responses={200: LoginResponseSerializer},
        tags=["인증"],
    )
    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")

        # 입력 검증
        if error := self._validate_credentials(email, password):
            return error

        # 잠금 상태 확인
        if AuthService.check_lockout(email):
            return Response(
                {"non_field_errors": ["로그인 시도 횟수 초과. 5분 후 다시 시도해주세요."]},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # 탈퇴 예약 계정 복구 시도
        AuthService.try_recover_account(email, password)

        # 인증 시도
        user = authenticate(request, username=email, password=password)

        if not user:
            remaining, error_msg = AuthService.handle_failed_login(email)
            return Response(
                {"non_field_errors": [error_msg]},
                status=(
                    status.HTTP_429_TOO_MANY_REQUESTS
                    if remaining == 0
                    else status.HTTP_401_UNAUTHORIZED
                ),
            )

        # 사용자 상태 확인
        if error := self._check_user_status(user):
            return error

        # 로그인 성공 처리
        user_with_stats = AuthService.handle_successful_login(request, user)

        return Response(
            {"message": "로그인 성공", "user": UserSerializer(user_with_stats).data},
            status=status.HTTP_200_OK,
        )

    def _validate_credentials(self, email: str, password: str) -> Response | None:
        """인증 정보 검증"""
        if not email or not password:
            return Response(
                {"non_field_errors": ["이메일과 비밀번호를 입력해주세요."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if "@" not in email:
            return Response(
                {"email": ["올바른 이메일 형식이 아닙니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return None

    def _check_user_status(self, user: Any) -> Response | None:
        """사용자 상태 확인"""
        if not user.is_active:
            return Response(
                {"non_field_errors": ["비활성화된 계정입니다."]},
                status=status.HTTP_403_FORBIDDEN,
            )

        if not user.email_verified:
            return Response(
                {
                    "non_field_errors": [
                        "이메일 인증이 필요합니다. 가입 시 받은 이메일의 인증 링크를 확인해주세요."
                    ]
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        return None


class LogoutView(APIView):
    """로그아웃"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(tags=["인증"])
    def post(self, request):
        AccountService.logout_user(request)
        return Response({"message": "로그아웃 되었습니다."}, status=status.HTTP_200_OK)


class SignUpView(APIView):
    """회원가입 - 이메일 인증 필수"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=UserSignUpSerializer,
        responses={
            201: {
                "type": "object",
                "properties": {"message": {"type": "string"}, "email": {"type": "string"}},
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = UserSignUpSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 비밀번호 일치 검증
        if error := check_passwords_match(
            serializer.validated_data["password"],
            serializer.validated_data["password2"],
        ):
            return error

        user = serializer.save()

        # 이메일 인증 토큰 생성 및 발송
        token = create_token(
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
            invalidate_existing=True,
        )
        send_verification_email(user.email, token.token)

        return Response(
            {
                "message": "회원가입 성공! 이메일로 전송된 인증 링크를 확인해주세요.",
                "email": user.email,
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema(tags=["프로필"])
class CurrentUserView(CurrentUserMixin, RetrieveAPIView):
    """현재 로그인한 유저 정보"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        response["Cache-Control"] = "private, max-age=60"
        return response


@extend_schema(tags=["프로필"])
class ProfileUpdateView(CurrentUserMixin, UpdateAPIView):
    """프로필 수정"""

    serializer_class = ProfileUpdateSerializer
    permission_classes = [IsAuthenticated]


class PasswordResetRequestView(APIView):
    """비밀번호 재설정 요청"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        success_message = "비밀번호 재설정 링크를 이메일로 전송했습니다."

        # 타이밍 공격 방지
        user, error_response = get_user_or_timing_safe_response(
            email=email, success_message=success_message, is_active_only=True
        )

        if error_response:
            return error_response

        # 비밀번호 재설정 토큰 생성 및 발송
        token = create_token(
            token_model=PasswordResetToken,
            user=user,
            expiry_hours=PASSWORD_RESET_HOURS,
            invalidate_existing=True,
        )
        send_password_reset_email(user.email, token.token)

        return Response({"message": success_message}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    """비밀번호 재설정 확인"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 비밀번호 일치 검증
        if error := check_passwords_match(
            serializer.validated_data["new_password"],
            serializer.validated_data["new_password2"],
            field_name="new_password",
        ):
            return error

        token_str = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        # 토큰 검증
        token, error_response = validate_token(PasswordResetToken, token_str)
        if error_response:
            return error_response

        # 비밀번호 재설정
        PasswordService.change_password(token.user, new_password)
        mark_token_as_used(token)

        return Response({"message": "비밀번호가 재설정되었습니다."}, status=status.HTTP_200_OK)


class PasswordChangeView(APIView):
    """비밀번호 변경 (로그인 상태)"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=PasswordChangeSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        current_password = serializer.validated_data["current_password"]
        new_password = serializer.validated_data["new_password"]
        new_password2 = serializer.validated_data["new_password2"]
        user = request.user

        # 현재 비밀번호 확인
        if not PasswordService.verify_current_password(user, current_password):
            return Response(
                {"current_password": ["현재 비밀번호가 일치하지 않습니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 새 비밀번호 일치 확인
        if error := check_passwords_match(new_password, new_password2, field_name="new_password"):
            return error

        # 현재 비밀번호와 새 비밀번호 동일 여부 확인
        if PasswordService.is_same_as_current(user, new_password):
            return Response(
                {"new_password": ["현재 비밀번호와 다른 비밀번호를 입력해주세요."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        PasswordService.change_password(user, new_password)

        return Response({"message": "비밀번호가 변경되었습니다."}, status=status.HTTP_200_OK)


class AccountDeleteView(APIView):
    """회원 탈퇴 (Soft Delete with 유예 기간)"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=AccountDeleteSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["계정"],
    )
    def post(self, request):
        serializer = AccountDeleteSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        password = serializer.validated_data["password"]
        user = request.user

        if not PasswordService.verify_current_password(user, password):
            return Response(
                {"password": ["비밀번호가 일치하지 않습니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        AccountService.schedule_deletion(user)
        AccountService.logout_user(request)

        return Response(
            {"message": "회원 탈퇴가 예약되었습니다. 1일 내 로그인하면 취소됩니다."},
            status=status.HTTP_200_OK,
        )


class EmailVerificationConfirmView(APIView):
    """이메일 인증 확인"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=EmailVerificationSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token_str = serializer.validated_data["token"]

        # 토큰 검증
        token, error_response = validate_token(
            token_model=EmailVerificationToken,
            token_str=token_str,
            error_messages={
                "not_found": "유효하지 않은 인증 링크입니다.",
                "invalid": "만료되었거나 이미 사용된 인증 링크입니다.",
            },
        )
        if error_response:
            return error_response

        # 이메일 인증 처리
        AccountService.verify_email(token.user)
        mark_token_as_used(token)

        return Response(
            {"message": "이메일 인증이 완료되었습니다. 이제 로그인할 수 있습니다."},
            status=status.HTTP_200_OK,
        )


class EmailVerificationResendView(APIView):
    """이메일 인증 재전송"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=EmailVerificationResendSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailVerificationResendSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        success_message = "인증 이메일을 전송했습니다."

        # 타이밍 공격 방지
        user, error_response = get_user_or_timing_safe_response(
            email=email, success_message=success_message, is_active_only=True
        )

        if error_response:
            return error_response

        if user.email_verified:
            return Response(
                {"email": ["이미 인증된 계정입니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 새 토큰 생성 및 발송
        token = create_token(
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
            invalidate_existing=True,
        )
        send_verification_email(user.email, token.token)

        return Response(
            {"message": "인증 이메일을 재전송했습니다."},
            status=status.HTTP_200_OK,
        )


class UserAvatarUpdateView(APIView):
    """유저 아바타 업데이트"""

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    @extend_schema(
        summary="아바타 이미지 업데이트",
        description="새 아바타 이미지를 업로드하고, 기존 아바타를 자동으로 삭제합니다.",
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {"avatar": {"type": "string", "format": "binary"}},
                "required": ["avatar"],
            }
        },
        responses={
            200: {
                "description": "업데이트 성공",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "아바타가 성공적으로 업데이트되었습니다.",
                            "avatar_url": "https://chessok.s3.ap-northeast-2.amazonaws.com/avatars/uuid.png",
                        }
                    }
                },
            },
            400: {"description": "잘못된 요청"},
        },
        tags=["프로필"],
    )
    def patch(self, request):
        file = request.FILES.get("avatar")

        if not file:
            return Response(
                {"avatar": ["아바타 파일이 필요합니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 파일 검증
        ext = self._validate_avatar_file(file)

        # 기존 아바타 키 추출
        old_avatar_key = self._extract_old_avatar_key(request.user)

        # 새 아바타 업로드
        new_avatar_url = self._upload_new_avatar(file, ext)

        # 유저 모델 업데이트
        request.user.avatar_url = new_avatar_url
        request.user.save(update_fields=["avatar_url"])

        # 기존 아바타 삭제 (실패해도 무시)
        if old_avatar_key:
            try:
                s3_uploader.delete_file(old_avatar_key)
            except Exception:
                pass

        return Response(
            {"message": "아바타가 성공적으로 업데이트되었습니다.", "avatar_url": new_avatar_url},
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        summary="아바타 이미지 삭제",
        description="현재 아바타 이미지를 삭제합니다.",
        responses={
            200: {
                "description": "삭제 성공",
                "content": {
                    "application/json": {"example": {"message": "아바타가 삭제되었습니다."}}
                },
            },
            400: {"description": "삭제할 아바타가 없음"},
        },
        tags=["프로필"],
    )
    def delete(self, request):
        user = request.user

        if not user.avatar_url:
            return Response(
                {"avatar": ["삭제할 아바타가 없습니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # S3에서 아바타 삭제
        old_avatar_key = self._extract_old_avatar_key(user)
        if old_avatar_key:
            try:
                s3_uploader.delete_file(old_avatar_key)
            except Exception:
                pass

        # 유저 모델 업데이트
        user.avatar_url = None
        user.save(update_fields=["avatar_url"])

        return Response({"message": "아바타가 삭제되었습니다."}, status=status.HTTP_200_OK)

    def _validate_avatar_file(self, file: Any) -> str:
        """아바타 파일 검증 및 확장자 반환"""
        file_name = file.name
        S3ImageValidator.validate_file_name(file_name)
        ext = file_name.rsplit(".", 1)[-1].lower()
        S3ImageValidator.validate_extension(file_name, ext)
        S3ImageValidator.validate_mime_type(ext, file.content_type)
        S3ImageValidator.validate_file_size(file.size)
        return ext

    def _extract_old_avatar_key(self, user: Any) -> str | None:
        """기존 아바타 키 추출"""
        if not user.avatar_url:
            return None
        return s3_uploader.extract_key_from_url(user.avatar_url)

    def _upload_new_avatar(self, file: Any, ext: str) -> str:
        """새 아바타를 S3에 업로드하고 URL 반환"""
        prefix = S3Constants.PATH_MAPPING[FileType.USER_AVATAR]
        key = f"{prefix}/{uuid.uuid4()}.{ext}"

        s3_uploader.get_s3_client().upload_fileobj(
            file.file,
            s3_uploader.get_bucket_name(),
            key,
            ExtraArgs={"ContentType": file.content_type},
        )

        return f"{s3_uploader.get_s3_base_url()}{key}"


class EmailCheckView(APIView):
    """이메일 중복 체크"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=EmailCheckSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "available": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailCheckSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=serializer.validated_data["email"]).first()
        return Response(check_availability(user, "이메일"), status=status.HTTP_200_OK)


class NicknameCheckView(APIView):
    """닉네임 중복 체크"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=NicknameCheckSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "available": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = NicknameCheckSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(nickname=serializer.validated_data["nickname"]).first()
        return Response(check_availability(user, "닉네임"), status=status.HTTP_200_OK)


class EmailChangeRequestView(APIView):
    """이메일 변경 요청"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=EmailChangeRequestSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["계정"],
    )
    def post(self, request):
        serializer = EmailChangeRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        new_email = serializer.validated_data["new_email"]
        password = serializer.validated_data["password"]
        user = request.user

        # 비밀번호 확인
        if not PasswordService.verify_current_password(user, password):
            return Response(
                {"password": ["비밀번호가 일치하지 않습니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 현재 이메일과 동일한지 확인
        if user.email == new_email:
            return Response(
                {"new_email": ["현재 이메일과 동일합니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 새 이메일 중복 확인
        if User.objects.filter(email=new_email).exists():
            return Response(
                {"new_email": ["이미 사용 중인 이메일입니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 이메일 변경 인증 토큰 생성 및 발송
        token = create_token(
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
            invalidate_existing=True,
        )

        # 토큰에 새 이메일 정보 저장 (캐시에 임시 저장)
        cache.set(f"email_change:{token.token}", new_email, EMAIL_VERIFICATION_HOURS * 3600)

        send_verification_email(new_email, token.token)

        return Response(
            {"message": f"인증 이메일을 {new_email}로 전송했습니다."},
            status=status.HTTP_200_OK,
        )


class EmailChangeConfirmView(APIView):
    """이메일 변경 확인"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=EmailChangeConfirmSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["계정"],
    )
    def post(self, request):
        serializer = EmailChangeConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token_str = serializer.validated_data["token"]
        user = request.user

        # 토큰 검증
        token, error_response = validate_token(
            token_model=EmailVerificationToken,
            token_str=token_str,
            error_messages={
                "not_found": "유효하지 않은 인증 토큰입니다.",
                "invalid": "만료되었거나 이미 사용된 토큰입니다.",
            },
        )
        if error_response:
            return error_response

        # 토큰 소유자 확인
        if token.user_id != user.id:
            return Response(
                {"token": ["본인의 인증 토큰이 아닙니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 캐시에서 새 이메일 가져오기
        new_email = cache.get(f"email_change:{token_str}")
        if not new_email:
            return Response(
                {"token": ["이메일 변경 요청이 만료되었습니다. 다시 시도해주세요."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 새 이메일 중복 재확인
        if User.objects.filter(email=new_email).exclude(pk=user.pk).exists():
            return Response(
                {"new_email": ["이미 사용 중인 이메일입니다."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 이메일 변경
        user.email = new_email
        user.save(update_fields=["email"])

        # 토큰 사용 처리 및 캐시 삭제
        mark_token_as_used(token)
        cache.delete(f"email_change:{token_str}")

        return Response(
            {"message": f"이메일이 {new_email}로 변경되었습니다."},
            status=status.HTTP_200_OK,
        )
