import re

from rest_framework import serializers

from accounts.models import User


class UserSerializer(serializers.ModelSerializer):
    """사용자 정보 조회용 Serializer"""

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "nickname",
            "rating",
            "games_played",
            "games_won",
            "games_lost",
            "games_draw",
            "avatar_url",
            "bio",
            "created_at",
        )
        read_only_fields = (
            "id",
            "rating",
            "games_played",
            "games_won",
            "games_lost",
            "games_draw",
            "created_at",
        )


class LoginRequestSerializer(serializers.Serializer):
    """로그인 요청"""

    email = serializers.EmailField(help_text="이메일 주소")
    password = serializers.CharField(write_only=True, help_text="비밀번호")


class LoginResponseSerializer(serializers.Serializer):
    """로그인 응답"""

    message = serializers.CharField()
    user = UserSerializer()


class UserSignUpSerializer(serializers.ModelSerializer):
    """회원가입용 Serializer (이메일 기반 로그인)"""

    password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="비밀번호 (최소 8자, 대문자, 특수문자 !, *, @ 중 1개 이상 포함)",
    )
    password2 = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}, help_text="비밀번호 확인"
    )

    class Meta:
        model = User
        fields = ("email", "nickname", "bio", "password", "password2")

    def validate_password(self, value):
        """비밀번호 커스텀 검증: 최소 길이 + 대문자 + 특수문자"""
        # 최소 길이 검증 (8자 이상)
        if len(value) < 8:
            raise serializers.ValidationError("비밀번호는 최소 8자 이상이어야 합니다.")

        # 대문자 검증
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("비밀번호에 대문자가 최소 1개 포함되어야 합니다.")

        # 특수문자 검증 (!, *, @ 중 하나)
        if not re.search(r"[!*@]", value):
            raise serializers.ValidationError(
                "비밀번호에 특수문자 (!, *, @) 중 1개 이상 포함되어야 합니다."
            )

        return value

    def validate(self, attrs):
        """비밀번호 일치 확인"""
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "비밀번호가 일치하지 않습니다."})
        return attrs

    def validate_email(self, value):
        """이메일 중복 체크"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("이미 사용 중인 이메일입니다.")
        return value

    def validate_nickname(self, value):
        """닉네임 중복 체크"""
        if User.objects.filter(nickname=value).exists():
            raise serializers.ValidationError("이미 사용 중인 닉네임입니다.")
        return value

    def create(self, validated_data):
        """사용자 생성"""
        validated_data.pop("password2")
        user = User.objects.create_user(**validated_data)
        return user


class ProfileUpdateSerializer(serializers.ModelSerializer):
    """프로필 수정용 Serializer"""

    class Meta:
        model = User
        fields = ("nickname", "bio", "avatar_url")

    def validate_nickname(self, value):
        """닉네임 중복 체크 (본인 제외)"""
        user = self.context["request"].user
        if User.objects.filter(nickname=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("이미 사용 중인 닉네임입니다.")
        return value
