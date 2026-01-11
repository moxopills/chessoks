"""사용자 인증 및 프로필 관련 View"""

from drf_spectacular.utils import extend_schema
from rest_framework.generics import RetrieveAPIView, UpdateAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.accounts.models import User
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
from apps.accounts.services import AccountSessionService, UserProfileService


class CurrentUserMixin:
    """현재 로그인한 유저를 stats와 함께 조회하는 Mixin"""

    def get_object(self):
        return User.objects.select_related("stats").get(pk=self.request.user.pk)


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

        result = AccountSessionService.login(request, email, password)
        if not result.ok:
            return Response(result.errors, status=result.status)

        user = result.payload["user"]
        message = result.payload["message"]
        return Response(
            {"message": message, "user": UserSerializer(user).data},
            status=result.status,
        )


class LogoutView(APIView):
    """로그아웃"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=None,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        result = AccountSessionService.logout(request)
        return Response(result.data, status=result.status)


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
        result = UserProfileService.signup(serializer)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


@extend_schema(tags=["프로필"])
class CurrentUserView(CurrentUserMixin, RetrieveAPIView):
    """현재 로그인한 유저 정보"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: UserSerializer})
    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        response["Cache-Control"] = "private, max-age=60"
        return response


@extend_schema(tags=["프로필"])
class ProfileUpdateView(CurrentUserMixin, UpdateAPIView):
    """프로필 수정"""

    serializer_class = ProfileUpdateSerializer
    permission_classes = [IsAuthenticated]

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
        result = UserProfileService.password_reset_request(serializer)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.password_reset_confirm(serializer)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.password_change(serializer, request.user)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = AccountSessionService.account_delete(serializer, request.user, request)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.email_verification_confirm(serializer)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.email_verification_resend(serializer)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.avatar_update(request.user, file)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)

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
        result = UserProfileService.avatar_delete(request.user)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.email_check(serializer)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.nickname_check(serializer)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.email_change_request(serializer, request.user)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)


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
        result = UserProfileService.email_change_confirm(serializer, request.user)
        if not result.ok:
            return Response(result.errors, status=result.status)

        return Response(result.data, status=result.status)
