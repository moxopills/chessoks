"""소셜 로그인 서비스"""

import logging

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

import requests
from rest_framework import serializers

from accounts.models import SocialUser

User = get_user_model()
logger = logging.getLogger(__name__)


class SocialAuthService:
    """소셜 인증 비즈니스 로직"""

    # OAuth API 엔드포인트
    OAUTH_ENDPOINTS = {
        "google": "https://www.googleapis.com/oauth2/v2/userinfo",
        "github": "https://api.github.com/user",
        "kakao": "https://kapi.kakao.com/v2/user/me",
        "naver": "https://openapi.naver.com/v1/nid/me",
    }

    @staticmethod
    def get_provider_user_info(provider: str, access_token: str) -> dict:
        """OAuth 제공자로부터 사용자 정보 조회

        Args:
            provider: OAuth 제공자 (google, github, kakao, naver)
            access_token: OAuth Access Token

        Returns:
            사용자 정보 dict (id, email, name 등)

        Raises:
            ValueError: 유효하지 않은 provider 또는 access_token
        """
        if provider not in SocialAuthService.OAUTH_ENDPOINTS:
            raise ValueError(f"지원하지 않는 provider: {provider}")

        endpoint = SocialAuthService.OAUTH_ENDPOINTS[provider]

        # Provider별 요청 헤더 설정
        if provider == "github":
            headers = {"Authorization": f"token {access_token}"}
        else:
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
    def _normalize_provider_data(provider: str, data: dict) -> dict:
        """Provider별 응답 데이터를 통일된 형식으로 변환

        Returns:
            {"id": str, "email": str, "name": str}
        """
        if provider == "google":
            return {
                "id": str(data["id"]),
                "email": data.get("email", ""),
                "name": data.get("name", ""),
            }

        elif provider == "github":
            return {
                "id": str(data["id"]),
                "email": data.get("email") or "",  # GitHub는 email이 null일 수 있음
                "name": data.get("name") or data.get("login", ""),
            }

        elif provider == "kakao":
            kakao_account = data.get("kakao_account", {})
            profile = kakao_account.get("profile", {})
            return {
                "id": str(data["id"]),
                "email": kakao_account.get("email", ""),
                "name": profile.get("nickname", ""),
            }

        elif provider == "naver":
            response = data.get("response", {})
            return {
                "id": response.get("id", ""),
                "email": response.get("email", ""),
                "name": response.get("name", ""),
            }

        else:
            raise ValueError(f"지원하지 않는 provider: {provider}")

    @staticmethod
    @transaction.atomic
    def create_or_update_user(
        provider: str, provider_data: dict, access_token: str, nickname: str = None
    ) -> User:
        """소셜 계정으로 유저 생성/조회 및 토큰 업데이트

        Args:
            provider: OAuth 제공자
            provider_data: OAuth에서 받은 사용자 정보
            access_token: OAuth Access Token
            nickname: 닉네임 (최초 가입 시 필수)

        Returns:
            User 객체

        Raises:
            serializers.ValidationError: 닉네임 필요 또는 중복
        """
        provider_user_id = provider_data["id"]
        email = provider_data.get("email", f"{provider}_{provider_user_id}@social.local")

        # 기존 소셜 계정 조회 (성능 최적화: select_related)
        social_user = (
            SocialUser.objects.filter(provider=provider, provider_user_id=provider_user_id)
            .select_related("user")
            .first()
        )

        if social_user:
            # 토큰 업데이트
            social_user.access_token = access_token
            social_user.extra_data = provider_data
            social_user.updated_at = timezone.now()
            social_user.save(update_fields=["access_token", "extra_data", "updated_at"])
            return social_user.user

        # 이메일로 기존 유저 확인 후 소셜 계정 연동
        user = User.objects.filter(email=email).first()
        if user:
            SocialUser.objects.create(
                user=user,
                provider=provider,
                provider_user_id=provider_user_id,
                access_token=access_token,
                extra_data=provider_data,
            )
            return user

        # 신규 유저 생성
        if not nickname:
            raise serializers.ValidationError({"nickname": "최초 가입 시 닉네임이 필요합니다."})

        # 닉네임 중복 체크
        if User.objects.filter(nickname=nickname).exists():
            raise serializers.ValidationError({"nickname": "이미 사용 중인 닉네임입니다."})

        user = User.objects.create_user(email=email, nickname=nickname, password=None)
        SocialUser.objects.create(
            user=user,
            provider=provider,
            provider_user_id=provider_user_id,
            access_token=access_token,
            extra_data=provider_data,
        )
        return user
