"""소셜 로그인 뷰"""

import secrets

from django.conf import settings
from django.contrib.auth import login
from django.http import HttpResponseRedirect
from django.urls import reverse

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.accounts.models import SocialUser
from apps.accounts.serializers import SocialAccountUnlinkSerializer, SocialUserSerializer
from apps.accounts.services.social_service import SocialAuthService


class SocialOAuthStartView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def get(self, request, provider: str):
        provider = provider.lower()
        if provider not in ("kakao", "naver"):
            return Response({"error": "지원하지 않는 provider입니다."}, status=400)
        state = secrets.token_urlsafe(16)
        request.session[f"social_state_{provider}"] = state
        next_url = request.GET.get("next") or "/"
        request.session[f"social_next_{provider}"] = next_url
        redirect_uri = SocialOAuthCallbackView.get_redirect_uri(request, provider)
        try:
            auth_url = SocialAuthService.get_authorization_url(provider, redirect_uri, state)
        except ValueError as exc:
            return Response({"error": str(exc)}, status=400)
        return HttpResponseRedirect(auth_url)


class SocialOAuthCallbackView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @staticmethod
    def get_redirect_uri(request, provider: str) -> str:
        if provider == "kakao" and settings.KAKAO_REDIRECT_URI:
            return settings.KAKAO_REDIRECT_URI
        if provider == "naver" and settings.NAVER_REDIRECT_URI:
            return settings.NAVER_REDIRECT_URI
        return request.build_absolute_uri(reverse("social:oauth-callback", args=[provider]))

    def get(self, request, provider: str):
        provider = provider.lower()
        if provider not in ("kakao", "naver"):
            return Response({"error": "지원하지 않는 provider입니다."}, status=400)
        code = request.GET.get("code")
        state = request.GET.get("state")
        if not code:
            return Response({"error": "인증 코드가 없습니다."}, status=400)
        expected_state = request.session.get(f"social_state_{provider}")
        if expected_state and state != expected_state:
            return Response({"error": "잘못된 요청입니다."}, status=400)
        redirect_uri = SocialOAuthCallbackView.get_redirect_uri(request, provider)
        try:
            access_token = SocialAuthService.exchange_code_for_token(
                provider, code, redirect_uri, state or ""
            )
            provider_data = SocialAuthService.get_provider_user_info(provider, access_token)
            user = SocialAuthService.create_or_update_user(
                provider=provider,
                provider_data=provider_data,
                nickname=None,
            )
        except ValueError as exc:
            return Response({"error": str(exc)}, status=400)

        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        next_url = request.session.get(f"social_next_{provider}") or "/"
        return HttpResponseRedirect(next_url)


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
