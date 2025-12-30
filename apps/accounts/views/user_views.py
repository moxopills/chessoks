from datetime import timedelta

from django.contrib.auth import authenticate, login, logout
from django.core.cache import cache
from django.utils import timezone

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.generics import RetrieveAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.accounts.models import PasswordResetToken, User
from apps.accounts.serializers import (
    LoginRequestSerializer,
    LoginResponseSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfileUpdateSerializer,
    UserSerializer,
    UserSignUpSerializer,
)
from apps.accounts.utils.email import send_password_reset_email


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
    """회원가입"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=UserSignUpSerializer,
        responses={201: LoginResponseSerializer},
        tags=["인증"],
    )
    def post(self, request):
        serializer = UserSignUpSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()
        user_data = UserSerializer(user).data

        return Response(
            {"message": "회원가입 성공", "user": user_data},
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

        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            # 보안: 존재하지 않는 이메일도 동일하게 처리 (타이밍 공격 방지)
            return Response(
                {"message": "비밀번호 재설정 링크를 이메일로 전송했습니다."},
                status=status.HTTP_200_OK,
            )

        PasswordResetToken.objects.filter(user=user, is_used=False).update(is_used=True)

        token = PasswordResetToken.objects.create(
            user=user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=1),
        )

        send_password_reset_email(user.email, token.token)

        return Response(
            {"message": "비밀번호 재설정 링크를 이메일로 전송했습니다."},
            status=status.HTTP_200_OK,
        )


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

        try:
            token = PasswordResetToken.objects.select_related("user").get(token=token_str)
        except PasswordResetToken.DoesNotExist:
            return Response(
                {"error": "유효하지 않은 토큰입니다."}, status=status.HTTP_400_BAD_REQUEST
            )

        if not token.is_valid:
            return Response(
                {"error": "만료되었거나 이미 사용된 토큰입니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = token.user
        user.set_password(new_password)
        user.save(update_fields=["password"])

        token.is_used = True
        token.used_at = timezone.now()
        token.save(update_fields=["is_used", "used_at"])

        return Response({"message": "비밀번호가 재설정되었습니다."}, status=status.HTTP_200_OK)
