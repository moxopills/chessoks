"""인증/계정/프로필 수정 관련 View."""

from drf_spectacular.utils import extend_schema
from rest_framework.generics import RetrieveAPIView, UpdateAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import APIView

from apps.accounts.models import User
from apps.accounts.permissions import IsAuthenticatedOrGuest
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
    SignupEmailConfirmSerializer,
    SignupEmailRequestSerializer,
    UserSerializer,
    UserSignUpSerializer,
)
from apps.accounts.services import AccountSessionService, UserProfileService
from apps.core.throttling import (
    AuthLoginThrottle,
    AuthPasswordResetThrottle,
    AuthSignupThrottle,
    AuthVerificationThrottle,
    AvatarUploadThrottle,
)


class CurrentUserMixin:
    """현재 로그인한 유저를 stats와 함께 조회하는 Mixin."""

    def get_object(self):
        return User.objects.select_related("stats").get(pk=self.request.user.pk)


class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthLoginThrottle]

    @extend_schema(
        request=LoginRequestSerializer, responses={200: LoginResponseSerializer}, tags=["인증"]
    )
    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")
        remember_raw = request.data.get("remember_me", False)
        if isinstance(remember_raw, bool):
            remember_me = remember_raw
        else:
            remember_me = str(remember_raw).lower() in {"1", "true", "on", "yes"}
        result = AccountSessionService.login(request, email, password, remember_me=remember_me)
        return Response(result.data, status=result.status)


class LogoutView(APIView):
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
    permission_classes = [AllowAny]
    throttle_classes = [AuthSignupThrottle]

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
        from django.contrib.auth import login

        serializer = UserSignUpSerializer(data=request.data)
        result = UserProfileService.signup(serializer)
        user_id = result.data.get("user_id")
        if user_id:
            user = User.objects.filter(pk=user_id).first()
            if user:
                login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        return Response(result.data, status=result.status)


class SignupEmailRequestView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthVerificationThrottle]

    @extend_schema(
        request=SignupEmailRequestSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {"message": {"type": "string"}, "email": {"type": "string"}},
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = SignupEmailRequestSerializer(data=request.data)
        result = UserProfileService.signup_email_request(serializer)
        return Response(result.data, status=result.status)


class SignupEmailConfirmView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthVerificationThrottle]

    @extend_schema(
        request=SignupEmailConfirmSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {"message": {"type": "string"}, "email": {"type": "string"}},
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = SignupEmailConfirmSerializer(data=request.data)
        result = UserProfileService.signup_email_confirm(serializer)
        return Response(result.data, status=result.status)


@extend_schema(tags=["프로필"])
class CurrentUserView(CurrentUserMixin, RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: UserSerializer})
    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response["Pragma"] = "no-cache"
        response["Expires"] = "0"
        return response


@extend_schema(tags=["프로필"])
class ProfileUpdateView(CurrentUserMixin, UpdateAPIView):
    serializer_class = ProfileUpdateSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(request=ProfileUpdateSerializer, responses={200: UserSerializer})
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data)
        UserProfileService.profile_update(serializer, user)
        fresh_user = User.objects.select_related("stats").get(pk=user.pk)
        return Response(UserSerializer(fresh_user).data)

    @extend_schema(request=ProfileUpdateSerializer, responses={200: UserSerializer})
    def partial_update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        UserProfileService.profile_update(serializer, user)
        fresh_user = User.objects.select_related("stats").get(pk=user.pk)
        return Response(UserSerializer(fresh_user).data)


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthPasswordResetThrottle]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        result = UserProfileService.password_reset_request(serializer)
        return Response(result.data, status=result.status)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthPasswordResetThrottle]

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        result = UserProfileService.password_reset_confirm(serializer)
        return Response(result.data, status=result.status)


class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=PasswordChangeSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={"request": request})
        result = UserProfileService.password_change(serializer, request.user, request)
        return Response(result.data, status=result.status)


class AccountDeleteView(APIView):
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
        return Response(result.data, status=result.status)


class EmailVerificationConfirmView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthVerificationThrottle]

    @extend_schema(
        request=EmailVerificationSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        result = UserProfileService.email_verification_confirm(serializer)
        return Response(result.data, status=result.status)


class EmailVerificationResendView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthVerificationThrottle]

    @extend_schema(
        request=EmailVerificationResendSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailVerificationResendSerializer(data=request.data)
        result = UserProfileService.email_verification_resend(serializer)
        return Response(result.data, status=result.status)


class UserAvatarUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [AvatarUploadThrottle]
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
        responses={200: {"description": "업데이트 성공"}, 400: {"description": "잘못된 요청"}},
        tags=["프로필"],
    )
    def patch(self, request):
        file = request.FILES.get("avatar")
        result = UserProfileService.avatar_update(request.user, file)
        return Response(result.data, status=result.status)

    @extend_schema(
        summary="아바타 이미지 삭제",
        description="현재 아바타 이미지를 삭제합니다.",
        responses={200: {"description": "삭제 성공"}, 400: {"description": "삭제할 아바타가 없음"}},
        tags=["프로필"],
    )
    def delete(self, request):
        result = UserProfileService.avatar_delete(request.user)
        return Response(result.data, status=result.status)


class EmailCheckView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthVerificationThrottle]

    @extend_schema(
        request=EmailCheckSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {"available": {"type": "boolean"}, "message": {"type": "string"}},
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailCheckSerializer(data=request.data)
        result = UserProfileService.email_check(serializer)
        return Response(result.data, status=result.status)


class NicknameCheckView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AuthVerificationThrottle]

    @extend_schema(
        request=NicknameCheckSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {"available": {"type": "boolean"}, "message": {"type": "string"}},
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = NicknameCheckSerializer(data=request.data)
        result = UserProfileService.nickname_check(serializer)
        return Response(result.data, status=result.status)


class EmailChangeRequestView(APIView):
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
        return Response(result.data, status=result.status)


class EmailChangeConfirmView(APIView):
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
        return Response(result.data, status=result.status)
