import uuid

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

from apps.accounts.models import EmailVerificationToken, PasswordResetToken
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


class LoginView(APIView):
    """로그인 - 3번 실패 시 5분 잠금"""

    permission_classes = [AllowAny]
    MAX_ATTEMPTS = 3
    LOCKOUT_DURATION = 300

    @extend_schema(
        request=LoginRequestSerializer,
        responses={200: LoginResponseSerializer},
        tags=["인증"],
    )
    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")

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

        lockout_key = f"login_lock:{email}"
        if cache.get(lockout_key):
            return Response(
                {"error": "로그인 시도 횟수 초과. 5분 후 다시 시도해주세요."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        user = authenticate(request, username=email, password=password)

        if user is None:
            attempts_key = f"login_fail:{email}"
            attempts = cache.get(attempts_key, 0) + 1

            if attempts >= self.MAX_ATTEMPTS:
                cache.set(lockout_key, 1, self.LOCKOUT_DURATION)
                cache.delete(attempts_key)
                return Response(
                    {"error": "로그인 3회 실패. 5분 후 다시 시도해주세요."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            cache.set(attempts_key, attempts, 300)
            return Response(
                {"error": f"로그인 실패. 남은 시도: {self.MAX_ATTEMPTS - attempts}회"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            return Response({"error": "비활성화된 계정입니다."}, status=status.HTTP_403_FORBIDDEN)

        if not user.email_verified:
            return Response(
                {
                    "error": "이메일 인증이 필요합니다. 가입 시 받은 이메일의 인증 링크를 확인해주세요."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        cache.delete(f"login_fail:{email}")
        login(request, user)

        # last_login 업데이트
        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        return Response(
            {"message": "로그인 성공", "user": UserSerializer(user).data},
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

        # 이메일 인증 토큰 생성 및 발송 (24시간 유효)
        token = create_token(
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=24,
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
class CurrentUserView(RetrieveAPIView):
    """현재 로그인한 유저 정보"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

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
        return self.request.user

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
            email=email,
            success_message=success_message,
            is_active_only=True,
        )

        if error_response:
            return error_response

        # 비밀번호 재설정 토큰 생성 (1시간 유효)
        token = create_token(
            token_model=PasswordResetToken,
            user=user,
            expiry_hours=1,
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
        request={"type": "object", "properties": {"token": {"type": "string"}}},
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
        request={"type": "object", "properties": {"email": {"type": "string"}}},
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
            email=email,
            success_message=success_message,
            is_active_only=True,
        )

        if error_response:
            return error_response

        # 이미 인증된 유저
        if user.email_verified:
            return Response(
                {"error": "이미 인증된 계정입니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 새 토큰 생성 및 발송 (24시간 유효)
        token = create_token(
            token_model=EmailVerificationToken,
            user=user,
            expiry_hours=24,
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
        tags=["User"],
    )
    def patch(self, request):
        """아바타 업데이트"""
        user = request.user
        file = request.FILES.get("avatar")

        if not file:
            return Response(
                {"error": "아바타 파일이 필요합니다."}, status=status.HTTP_400_BAD_REQUEST
            )

        # 파일 검증
        file_name = file.name
        content_type = file.content_type

        S3ImageValidator.validate_file_name(file_name)
        ext = file_name.rsplit(".", 1)[-1].lower()
        S3ImageValidator.validate_extension(file_name, ext)
        S3ImageValidator.validate_mime_type(ext, content_type)
        S3ImageValidator.validate_file_size(file.size)

        # 기존 아바타 키 추출 (삭제용)
        old_avatar_key = None
        if user.avatar_url:
            old_avatar_key = s3_uploader.extract_key_from_url(user.avatar_url)

        # 새 아바타 업로드
        prefix = S3Constants.PATH_MAPPING.get(FileType.USER_AVATAR)
        key = f"{prefix}/{uuid.uuid4()}.{ext}"

        s3_client = s3_uploader.get_s3_client()
        bucket = s3_uploader.get_bucket_name()

        s3_client.upload_fileobj(
            file.file,
            bucket,
            key,
            ExtraArgs={"ContentType": content_type},
        )

        new_avatar_url = f"{s3_uploader.get_s3_base_url()}{key}"

        # 유저 모델 업데이트
        user.avatar_url = new_avatar_url
        user.save(update_fields=["avatar_url"])

        # 기존 아바타 삭제 (있으면)
        if old_avatar_key:
            try:
                s3_uploader.delete_file(old_avatar_key)
            except Exception:
                # 삭제 실패해도 새 아바타는 저장됨 (로그만 남기고 무시)
                pass

        return Response(
            {
                "message": "아바타가 성공적으로 업데이트되었습니다.",
                "avatar_url": new_avatar_url,
            },
            status=status.HTTP_200_OK,
        )
