"""소셜 로그인 서비스"""

import logging
import random
import re
import string
from urllib.parse import urlencode

from django.conf import settings
from django.db import transaction
from django.utils import timezone

import requests
from rest_framework import serializers

from apps.accounts.models import SocialUser, User

logger = logging.getLogger(__name__)


class SocialAuthService:
    """소셜 인증 비즈니스 로직"""

    # OAuth API 엔드포인트
    OAUTH_ENDPOINTS = {
        "kakao": "https://kapi.kakao.com/v2/user/me",
        "naver": "https://openapi.naver.com/v1/nid/me",
    }

    AUTH_ENDPOINTS = {
        "kakao": "https://kauth.kakao.com/oauth/authorize",
        "naver": "https://nid.naver.com/oauth2.0/authorize",
    }

    TOKEN_ENDPOINTS = {
        "kakao": "https://kauth.kakao.com/oauth/token",
        "naver": "https://nid.naver.com/oauth2.0/token",
    }

    @staticmethod
    def get_provider_user_info(provider: str, access_token: str) -> dict:
        """OAuth 제공자로부터 사용자 정보 조회

        Args:
            provider: OAuth 제공자 (kakao, naver)
            access_token: OAuth Access Token

        Returns:
            사용자 정보 dict (id, email, name 등)

        Raises:
            ValueError: 유효하지 않은 provider 또는 access_token
        """
        if provider not in SocialAuthService.OAUTH_ENDPOINTS:
            raise ValueError(f"지원하지 않는 provider: {provider}")

        endpoint = SocialAuthService.OAUTH_ENDPOINTS[provider]

        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(endpoint, headers=headers, timeout=10)

            if response.status_code == 401:
                logger.warning(f"{provider} OAuth: 유효하지 않은 access_token")
                raise ValueError("유효하지 않은 access token입니다.")

            if response.status_code != 200:
                logger.error(f"{provider} OAuth API 오류: {response.status_code} - {response.text}")
                raise ValueError(f"{provider} 사용자 정보를 가져올 수 없습니다.")

            data = response.json()

            # Provider별 응답 데이터 정규화
            return SocialAuthService._normalize_provider_data(provider, data)

        except requests.exceptions.RequestException as e:
            logger.error(f"{provider} OAuth API 요청 실패: {str(e)}")
            raise ValueError(f"{provider} 서버와 통신할 수 없습니다.") from None

    @staticmethod
    def get_authorization_url(provider: str, redirect_uri: str, state: str) -> str:
        if provider not in SocialAuthService.AUTH_ENDPOINTS:
            raise ValueError(f"지원하지 않는 provider: {provider}")
        client_id = SocialAuthService._get_client_id(provider)
        if not client_id:
            raise ValueError("소셜 로그인 설정이 필요합니다.")
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        if provider == "kakao":
            params["scope"] = "account_email,profile_nickname"
        return f"{SocialAuthService.AUTH_ENDPOINTS[provider]}?{urlencode(params)}"

    @staticmethod
    def exchange_code_for_token(provider: str, code: str, redirect_uri: str, state: str) -> str:
        if provider not in SocialAuthService.TOKEN_ENDPOINTS:
            raise ValueError(f"지원하지 않는 provider: {provider}")
        client_id = SocialAuthService._get_client_id(provider)
        client_secret = SocialAuthService._get_client_secret(provider)
        if not client_id:
            raise ValueError("소셜 로그인 설정이 필요합니다.")
        if provider == "kakao":
            data = {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code": code,
            }
            if client_secret:
                data["client_secret"] = client_secret
            response = requests.post(
                SocialAuthService.TOKEN_ENDPOINTS[provider], data=data, timeout=10
            )
        else:
            params = {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "state": state,
            }
            response = requests.get(
                SocialAuthService.TOKEN_ENDPOINTS[provider], params=params, timeout=10
            )

        if response.status_code != 200:
            logger.error("%s OAuth 토큰 교환 실패: %s", provider, response.text)
            raise ValueError("소셜 로그인 인증에 실패했습니다.")
        data = response.json()
        access_token = data.get("access_token")
        if not access_token:
            raise ValueError("소셜 로그인 인증에 실패했습니다.")
        return access_token

    @staticmethod
    def _normalize_provider_data(provider: str, data: dict) -> dict:
        """Provider별 응답 데이터를 통일된 형식으로 변환

        Returns:
            {"id": str, "email": str, "name": str}
        """
        if provider == "kakao":
            kakao_account = data.get("kakao_account", {})
            profile = kakao_account.get("profile", {})
            return {
                "id": str(data["id"]),
                "email": kakao_account.get("email", ""),
                "name": profile.get("nickname", ""),
            }

        if provider == "naver":
            response = data.get("response", {})
            return {
                "id": response.get("id", ""),
                "email": response.get("email", ""),
                "name": response.get("nickname", ""),  # 별명 사용
                "profile_image": response.get("profile_image", ""),
            }

        raise ValueError(f"지원하지 않는 provider: {provider}")

    @staticmethod
    def _get_client_id(provider: str) -> str:
        if provider == "kakao":
            return settings.KAKAO_CLIENT_ID
        if provider == "naver":
            return settings.NAVER_CLIENT_ID
        return ""

    @staticmethod
    def _get_client_secret(provider: str) -> str:
        if provider == "kakao":
            return settings.KAKAO_CLIENT_SECRET
        if provider == "naver":
            return settings.NAVER_CLIENT_SECRET
        return ""

    @staticmethod
    def _generate_nickname(base: str) -> str:
        base = re.sub(r"\s+", "", base or "")
        base = base[:20] if base else ""
        if not base:
            base = "user"
        for _ in range(6):
            candidate = base
            if User.objects.filter(nickname=candidate).exists():
                suffix = "".join(random.choices(string.digits, k=4))
                candidate = f"{base}{suffix}"
            if not User.objects.filter(nickname=candidate).exists():
                return candidate
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{base}{suffix}"

    @staticmethod
    @transaction.atomic
    def create_or_update_user(
        provider: str, provider_data: dict, nickname: str | None = None
    ) -> User:
        """소셜 계정으로 유저 생성/조회 (토큰은 저장하지 않음)

        Args:
            provider: OAuth 제공자
            provider_data: OAuth에서 받은 사용자 정보
            nickname: 닉네임 (최초 가입 시 필수)

        Returns:
            User 객체

        Raises:
            serializers.ValidationError: 닉네임 필요 또는 중복
        """
        provider_user_id = provider_data["id"]
        email = provider_data.get("email") or f"{provider}_{provider_user_id}@social.local"

        # 기존 소셜 계정 조회 (성능 최적화: select_related)
        social_user = (
            SocialUser.objects.filter(provider=provider, provider_user_id=provider_user_id)
            .select_related("user")
            .first()
        )

        if social_user:
            # extra_data만 업데이트 (프로필 정보 갱신용)
            social_user.extra_data = provider_data
            social_user.save(update_fields=["extra_data", "updated_at"])
            return social_user.user

        # 이메일로 기존 유저 확인 후 소셜 계정 연동
        user = User.objects.filter(email=email).first()
        if user:
            if user.social_users.exists():
                raise serializers.ValidationError(
                    {"provider": "이미 다른 소셜 계정이 연동되어 있습니다."}
                )

            # 소셜 계정 연동 시 이메일 자동 인증
            if not user.email_verified:
                user.email_verified = True
                user.email_verified_at = timezone.now()
                user.save(update_fields=["email_verified", "email_verified_at"])

            SocialUser.objects.create(
                user=user,
                provider=provider,
                provider_user_id=provider_user_id,
                extra_data=provider_data,
            )
            return user

        # 신규 유저 생성
        if not nickname:
            nickname = SocialAuthService._generate_nickname(provider_data.get("name") or provider)
        else:
            if User.objects.filter(nickname=nickname).exists():
                raise serializers.ValidationError({"nickname": "이미 사용 중인 닉네임입니다."})

        # 소셜 로그인 유저는 자동 인증
        user = User.objects.create_user(email=email, nickname=nickname, password=None)
        user.email_verified = True
        user.email_verified_at = timezone.now()

        # 프로필 사진이 있으면 아바타로 저장
        profile_image = provider_data.get("profile_image")
        if profile_image:
            user.avatar_url = profile_image

        user.save(update_fields=["email_verified", "email_verified_at", "avatar_url"])
        SocialUser.objects.create(
            user=user,
            provider=provider,
            provider_user_id=provider_user_id,
            extra_data=provider_data,
        )
        return user
