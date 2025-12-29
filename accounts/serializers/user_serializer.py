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
        if len(value) < 8:
            raise serializers.ValidationError("비밀번호는 최소 8자 이상이어야 합니다.")
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("비밀번호에 대문자가 최소 1개 포함되어야 합니다.")
        if not re.search(r"[!*@]", value):
            raise serializers.ValidationError(
                "비밀번호에 특수문자 (!, *, @) 중 1개 이상 포함되어야 합니다."
            )
        return value

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "비밀번호가 일치하지 않습니다."})
        return attrs

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("이미 사용 중인 이메일입니다.")
        return value

    def validate_nickname(self, value):
        if User.objects.filter(nickname=value).exists():
            raise serializers.ValidationError("이미 사용 중인 닉네임입니다.")
        return value

    def create(self, validated_data):
        validated_data.pop("password2")
        user = User.objects.create_user(**validated_data)
        return user


class ProfileUpdateSerializer(serializers.ModelSerializer):
    """프로필 수정용 Serializer"""

    class Meta:
        model = User
        fields = ("nickname", "bio", "avatar_url")

    def validate_nickname(self, value):
        user = self.context["request"].user
        if User.objects.filter(nickname=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("이미 사용 중인 닉네임입니다.")
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    """비밀번호 재설정 요청"""

    email = serializers.EmailField(help_text="가입된 이메일 주소")


class PasswordResetConfirmSerializer(serializers.Serializer):
    """비밀번호 재설정 확인"""

    token = serializers.CharField(help_text="이메일로 받은 토큰")
    new_password = serializers.CharField(write_only=True, help_text="새 비밀번호")
    new_password2 = serializers.CharField(write_only=True, help_text="비밀번호 확인")

    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("비밀번호는 최소 8자 이상이어야 합니다.")
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("비밀번호에 대문자가 최소 1개 포함되어야 합니다.")
        if not re.search(r"[!*@]", value):
            raise serializers.ValidationError(
                "비밀번호에 특수문자 (!, *, @) 중 1개 이상 포함되어야 합니다."
            )
        return value

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError({"new_password": "비밀번호가 일치하지 않습니다."})
        return attrs
