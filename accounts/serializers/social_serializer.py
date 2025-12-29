"""소셜 로그인 시리얼라이저"""

from django.contrib.auth import get_user_model, login
from django.db import transaction
from django.utils import timezone

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from accounts.models import SocialUser

User = get_user_model()


class SocialLoginSerializer(serializers.Serializer):
    """소셜 로그인 요청"""

    provider = serializers.ChoiceField(
        choices=SocialUser.PROVIDER_CHOICES, help_text="OAuth 제공자"
    )
    access_token = serializers.CharField(min_length=10, help_text="OAuth Access Token")
    nickname = serializers.CharField(
        required=False, max_length=50, help_text="닉네임 (최초 가입 시 필수)"
    )

    def validate_nickname(self, value):
        """닉네임 중복 체크"""
        if value and User.objects.filter(nickname=value).exists():
            raise serializers.ValidationError("이미 사용 중인 닉네임입니다.")
        return value

    def get_provider_user_info(self, provider, access_token):
        """OAuth 제공자로부터 사용자 정보 조회 (TODO: 실제 API 구현)"""
        # Mock data - 실제 구현 시 각 provider의 API 호출
        mock_data = {
            "google": lambda: {
                "id": "google_123",
                "email": "user@gmail.com",
                "name": "Google User",
            },
            "github": lambda: {
                "id": "github_456",
                "email": "user@github.com",
                "name": "GitHub User",
            },
            "kakao": lambda: {
                "id": "kakao_789",
                "email": "user@kakao.com",
                "name": "Kakao User",
            },
            "naver": lambda: {
                "id": "naver_012",
                "email": "user@naver.com",
                "name": "Naver User",
            },
        }
        return mock_data.get(provider, lambda: {})()

    @transaction.atomic
    def create_or_update_user(self, provider, provider_data, nickname=None):
        """소셜 계정으로 유저 생성/조회 및 토큰 업데이트"""
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
            social_user.access_token = self.validated_data["access_token"]
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
                access_token=self.validated_data["access_token"],
                extra_data=provider_data,
            )
            return user

        # 신규 유저 생성
        if not nickname:
            raise serializers.ValidationError({"nickname": "최초 가입 시 닉네임이 필요합니다."})

        user = User.objects.create_user(email=email, nickname=nickname, password=None)
        SocialUser.objects.create(
            user=user,
            provider=provider,
            provider_user_id=provider_user_id,
            access_token=self.validated_data["access_token"],
            extra_data=provider_data,
        )
        return user

    def save(self, request):
        """소셜 로그인 처리"""
        provider = self.validated_data["provider"]
        access_token = self.validated_data["access_token"]
        nickname = self.validated_data.get("nickname")

        # OAuth 사용자 정보 조회
        provider_data = self.get_provider_user_info(provider, access_token)
        if not provider_data:
            raise serializers.ValidationError("유효하지 않은 Access Token입니다.")

        # 유저 생성/조회 및 로그인
        user = self.create_or_update_user(provider, provider_data, nickname)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")

        return user


class SocialUserSerializer(serializers.ModelSerializer):
    """소셜 계정 조회"""

    provider_display = serializers.CharField(source="get_provider_display", read_only=True)

    @extend_schema_field(serializers.BooleanField)
    def get_is_token_expired(self, obj):
        """토큰 만료 여부"""
        return obj.is_token_expired

    is_token_expired = serializers.SerializerMethodField()

    class Meta:
        model = SocialUser
        fields = (
            "id",
            "provider",
            "provider_display",
            "provider_user_id",
            "is_token_expired",
            "created_at",
        )


class SocialAccountUnlinkSerializer(serializers.Serializer):
    """소셜 계정 연동 해제"""

    provider = serializers.ChoiceField(choices=SocialUser.PROVIDER_CHOICES, help_text="제공자")

    def validate(self, attrs):
        """연동 해제 가능 여부 검증"""
        user = self.context["request"].user
        provider = attrs["provider"]

        # 연동된 소셜 계정 확인
        if not SocialUser.objects.filter(user=user, provider=provider).exists():
            raise serializers.ValidationError({"provider": "연동되지 않은 계정입니다."})

        # 마지막 로그인 수단 확인 (성능 최적화: count 대신 exists + aggregate)
        social_count = SocialUser.objects.filter(user=user).count()
        if social_count == 1 and not user.has_usable_password():
            raise serializers.ValidationError(
                {
                    "provider": "마지막 로그인 수단입니다. 비밀번호 설정 또는 다른 소셜 계정 연동 후 해제 가능합니다."
                }
            )

        return attrs

    def save(self):
        """연동 해제 실행"""
        user = self.context["request"].user
        provider = self.validated_data["provider"]

        deleted_count, _ = SocialUser.objects.filter(user=user, provider=provider).delete()

        if deleted_count:
            return {"message": f"{dict(SocialUser.PROVIDER_CHOICES)[provider]} 연동 해제됨"}
        return {"message": "연동 해제 실패"}
