"""소셜 로그인 뷰"""

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from accounts.models import SocialUser
from accounts.serializers import (
    LoginResponseSerializer,
    SocialAccountUnlinkSerializer,
    SocialLoginSerializer,
    SocialUserSerializer,
    UserSerializer,
)


class SocialLoginView(APIView):
    """소셜 로그인"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=SocialLoginSerializer,
        responses={200: LoginResponseSerializer},
        tags=["소셜 인증"],
    )
    def post(self, request):
        serializer = SocialLoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save(request)
        user_data = UserSerializer(user).data

        return Response(
            {"message": "소셜 로그인 성공", "user": user_data}, status=status.HTTP_200_OK
        )


class SocialAccountListView(ListAPIView):
    """연동된 소셜 계정 목록"""

    serializer_class = SocialUserSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get_queryset(self):
        return SocialUser.objects.filter(user=self.request.user).select_related("user")

    @extend_schema(tags=["소셜 인증"])
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class SocialAccountUnlinkView(APIView):
    """소셜 계정 연동 해제"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=SocialAccountUnlinkSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["소셜 인증"],
    )
    def delete(self, request):
        serializer = SocialAccountUnlinkSerializer(data=request.data, context={"request": request})

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        result = serializer.save()
        return Response(result, status=status.HTTP_200_OK)
