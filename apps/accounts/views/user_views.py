import uuid
from typing import Any

from django.contrib.auth import authenticate, login, logout
from django.core.cache import cache
from django.utils import timezone

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
    EmailVerificationResendSerializer,
    EmailVerificationSerializer,
    LoginRequestSerializer,
    LoginResponseSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfileUpdateSerializer,
    UserSerializer,
    UserSignUpSerializer,
)
from apps.accounts.utils import (
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
MAX_LOGIN_ATTEMPTS = 3
LOGIN_LOCKOUT_DURATION = 300  # 5분
EMAIL_VERIFICATION_HOURS = 24
PASSWORD_RESET_HOURS = 1


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
        if validation_error := self._validate_credentials(email, password):
            return validation_error

        # 잠금 상태 확인
        if lockout_response := self._check_lockout(email):
            return lockout_response

        # 인증 시도
        user = authenticate(request, username=email, password=password)

        if not user:
            return self._handle_failed_login(email)

        # 사용자 상태 확인
        if status_error := self._check_user_status(user):
            return status_error

        # 로그인 성공 처리
        return self._handle_successful_login(request, user, email)

    def _validate_credentials(self, email: str, password: str) -> Response | None:
        """인증 정보 검증"""
        if not email or not password:
            return Response(
                {"error": "이메일과 비밀번호를 입력해주세요."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if "@" not in email:
            return Response(
                {"error": "올바른 이메일 형식이 아닙니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return None

    def _check_lockout(self, email: str) -> Response | None:
        """잠금 상태 확인"""
        lockout_key = f"login_lock:{email}"
        if cache.get(lockout_key):
            return Response(
                {"error": "로그인 시도 횟수 초과. 5분 후 다시 시도해주세요."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        return None

    def _handle_failed_login(self, email: str) -> Response:
        """로그인 실패 처리"""
        attempts_key = f"login_fail:{email}"
        attempts = cache.get(attempts_key, 0) + 1

        if attempts >= MAX_LOGIN_ATTEMPTS:
            cache.set(f"login_lock:{email}", 1, LOGIN_LOCKOUT_DURATION)
            cache.delete(attempts_key)
            return Response(
                {"error": "로그인 3회 실패. 5분 후 다시 시도해주세요."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        cache.set(attempts_key, attempts, LOGIN_LOCKOUT_DURATION)
        return Response(
            {"error": f"로그인 실패. 남은 시도: {MAX_LOGIN_ATTEMPTS - attempts}회"},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    def _check_user_status(self, user: Any) -> Response | None:
        """사용자 상태 확인"""
        if not user.is_active:
            return Response({"error": "비활성화된 계정입니다."}, status=status.HTTP_403_FORBIDDEN)

        if not user.email_verified:
            return Response(
                {
                    "error": "이메일 인증이 필요합니다. 가입 시 받은 이메일의 인증 링크를 확인해주세요."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        return None

    def _handle_successful_login(self, request: Any, user: Any, email: str) -> Response:
        """로그인 성공 처리"""
        cache.delete(f"login_fail:{email}")
        login(request, user)

        # last_login 업데이트
        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        # N+1 방지: stats를 미리 로드
        user_with_stats = User.objects.select_related("stats").get(pk=user.pk)

        return Response(
            {"message": "로그인 성공", "user": UserSerializer(user_with_stats).data},
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    """로그아웃"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(tags=["인증"])
    def post(self, request):
        logout(request)
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

        user = serializer.save()

        # 이메일 인증 토큰 생성 및 발송
        self._send_email_verification(user)

        return Response(
            {
                "message": "회원가입 성공! 이메일로 전송된 인증 링크를 확인해주세요.",
                "email": user.email,
            },
            status=status.HTTP_201_CREATED,
        )

    def _send_email_verification(self, user: Any) -> None:
        """이메일 인증 토큰 생성 및 발송"""
        token = create_token(
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=EMAIL_VERIFICATION_HOURS,
            invalidate_existing=True,
        )
        send_verification_email(user.email, token.token)


@extend_schema(tags=["프로필"])
class CurrentUserView(RetrieveAPIView):
    """현재 로그인한 유저 정보"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # N+1 방지: stats를 미리 로드
        return User.objects.select_related("stats").get(pk=self.request.user.pk)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        response = Response(serializer.data)
        response["Cache-Control"] = "private, max-age=60"
        return response


@extend_schema(tags=["프로필"])
class ProfileUpdateView(UpdateAPIView):
    """프로필 수정"""

    serializer_class = ProfileUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # N+1 방지: stats를 미리 로드
        return User.objects.select_related("stats").get(pk=self.request.user.pk)

    @extend_schema(request=ProfileUpdateSerializer, responses={200: UserSerializer})
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(request=ProfileUpdateSerializer, responses={200: UserSerializer})
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)


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

        token_str = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        # 토큰 검증
        token, error_response = validate_token(PasswordResetToken, token_str)
        if error_response:
            return error_response

        # 비밀번호 재설정
        user = token.user
        user.set_password(new_password)
        user.save(update_fields=["password"])

        # 토큰 사용 완료 처리
        mark_token_as_used(token)

        return Response({"message": "비밀번호가 재설정되었습니다."}, status=status.HTTP_200_OK)


class EmailVerificationConfirmView(APIView):
    """이메일 인증 확인 - 토큰으로 이메일 검증"""

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
        user = token.user
        user.email_verified = True
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified", "email_verified_at"])

        # 토큰 사용 완료 처리
        mark_token_as_used(token)

        return Response(
            {"message": "이메일 인증이 완료되었습니다. 이제 로그인할 수 있습니다."},
            status=status.HTTP_200_OK,
        )


class EmailVerificationResendView(APIView):
    """이메일 인증 재전송 - 미인증 유저 대상"""

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

        # 이미 인증된 유저
        if user.email_verified:
            return Response(
                {"error": "이미 인증된 계정입니다."},
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
    """유저 아바타 업데이트 - 업로드 + 저장 + 기존 삭제"""

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    @extend_schema(
        summary="아바타 이미지 업데이트",
        description="새 아바타 이미지를 업로드하고, 기존 아바타를 자동으로 삭제합니다.",
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "avatar": {"type": "string", "format": "binary"},
                },
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
            400: {"description": "잘못된 요청 (파일 누락, 검증 실패 등)"},
        },
        tags=["프로필"],
    )
    def patch(self, request):
        """아바타 업데이트"""
        file = request.FILES.get("avatar")

        if not file:
            return Response(
                {"error": "아바타 파일이 필요합니다."}, status=status.HTTP_400_BAD_REQUEST
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

        # 기존 아바타 삭제
        self._delete_old_avatar(old_avatar_key)

        return Response(
            {
                "message": "아바타가 성공적으로 업데이트되었습니다.",
                "avatar_url": new_avatar_url,
            },
            status=status.HTTP_200_OK,
        )

    def _validate_avatar_file(self, file: Any) -> str:
        """아바타 파일 검증 및 확장자 반환"""
        file_name = file.name
        content_type = file.content_type

        S3ImageValidator.validate_file_name(file_name)
        ext = file_name.rsplit(".", 1)[-1].lower()
        S3ImageValidator.validate_extension(file_name, ext)
        S3ImageValidator.validate_mime_type(ext, content_type)
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

    def _delete_old_avatar(self, old_avatar_key: str | None) -> None:
        """기존 아바타 삭제 (실패 시 무시)"""
        if not old_avatar_key:
            return

        try:
            s3_uploader.delete_file(old_avatar_key)
        except Exception:
            # 삭제 실패해도 새 아바타는 저장됨 (로그만 남기고 무시)
            pass
