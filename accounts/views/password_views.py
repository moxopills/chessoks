"""비밀번호 재설정 뷰"""

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from accounts.serializers import (
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
)
from accounts.services.password_service import PasswordResetService


class PasswordResetRequestView(APIView):
    """비밀번호 재설정 요청 (이메일 전송)"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        PasswordResetService.create_reset_token(email)

        # 보안: 이메일 존재 여부와 관계없이 동일한 응답
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
        tags=["인증"],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        success, message = PasswordResetService.reset_password(token, new_password)

        if success:
            return Response({"message": message}, status=status.HTTP_200_OK)
        return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)
