from rest_framework import serializers

from apps.accounts.models import User
from apps.accounts.utils.validators import validate_password_strength


class UserStatsSerializer(serializers.Serializer):
    """사용자 게임 통계 (읽기 전용)"""

    rating = serializers.IntegerField(read_only=True)
    games_played = serializers.IntegerField(read_only=True)
    games_won = serializers.IntegerField(read_only=True)
    games_lost = serializers.IntegerField(read_only=True)
    games_draw = serializers.IntegerField(read_only=True)
    win_rate = serializers.FloatField(read_only=True)


class UserSerializer(serializers.ModelSerializer):
    """사용자 정보 조회용 Serializer"""

    stats = UserStatsSerializer(read_only=True)

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "nickname",
            "avatar_url",
            "bio",
            "created_at",
            "stats",
        )
        read_only_fields = (
            "id",
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
        help_text="비밀번호 (최소 8자, 대소문자, 숫자, 특수문자 각 1개 이상)",
    )
    password2 = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}, help_text="비밀번호 확인"
    )

    class Meta:
        model = User
        fields = ("email", "nickname", "bio", "password", "password2")

    def validate_password(self, value):
        return validate_password_strength(value)

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
    new_password = serializers.CharField(
        write_only=True, help_text="새 비밀번호 (최소 8자, 대소문자, 숫자, 특수문자 각 1개 이상)"
    )
    new_password2 = serializers.CharField(write_only=True, help_text="비밀번호 확인")

    def validate_new_password(self, value):
        return validate_password_strength(value)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError({"new_password": "비밀번호가 일치하지 않습니다."})
        return attrs
