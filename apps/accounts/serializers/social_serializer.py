"""소셜 로그인 시리얼라이저"""

from django.contrib.auth import get_user_model

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from apps.accounts.models import SocialUser

User = get_user_model()


class SocialLoginSerializer(serializers.Serializer):
    """소셜 로그인 요청 - 데이터 검증만 담당"""

    provider = serializers.ChoiceField(
        choices=SocialUser.PROVIDER_CHOICES, help_text="OAuth 제공자"
    )
    access_token = serializers.CharField(min_length=10, help_text="OAuth Access Token")
    nickname = serializers.CharField(
        required=False, max_length=50, help_text="닉네임 (최초 가입 시 필수)"
    )


class SocialUserSerializer(serializers.ModelSerializer):
    """소셜 계정 조회"""

    provider_display = serializers.CharField(source="get_provider_display", read_only=True)

    @extend_schema_field(serializers.BooleanField)
    def get_is_token_expired(self, obj):
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
        user = self.context["request"].user
        provider = attrs["provider"]

        if not SocialUser.objects.filter(user=user, provider=provider).exists():
            raise serializers.ValidationError({"provider": "연동되지 않은 계정입니다."})

        social_count = SocialUser.objects.filter(user=user).count()
        if social_count == 1 and not user.has_usable_password():
            raise serializers.ValidationError(
                {
                    "provider": "마지막 로그인 수단입니다. 비밀번호 설정 또는 다른 소셜 계정 연동 후 해제 가능합니다."
                }
            )

        return attrs

    def save(self):
        user = self.context["request"].user
        provider = self.validated_data["provider"]

        deleted_count, _ = SocialUser.objects.filter(user=user, provider=provider).delete()

        if deleted_count:
            return {"message": f"{dict(SocialUser.PROVIDER_CHOICES)[provider]} 연동 해제됨"}
        return {"message": "연동 해제 실패"}
