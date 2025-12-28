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

from accounts.models import User
from accounts.serializers import (
    LoginRequestSerializer,
    LoginResponseSerializer,
    ProfileUpdateSerializer,
    UserSerializer,
    UserSignUpSerializer,
)


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
        User.objects.filter(pk=user.pk).update(last_login_at=timezone.now())

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


class CurrentUserView(RetrieveAPIView):
    """현재 로그인한 유저 정보"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    @extend_schema(tags=["인증"])
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        response = Response(serializer.data)
        response["Cache-Control"] = "private, max-age=60"
        return response


class ProfileUpdateView(UpdateAPIView):
    """프로필 수정"""

    serializer_class = ProfileUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    @extend_schema(
        request=ProfileUpdateSerializer, responses={200: UserSerializer}, tags=["프로필"]
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(
        request=ProfileUpdateSerializer, responses={200: UserSerializer}, tags=["프로필"]
    )
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)
