from rest_framework import serializers

from apps.accounts.models import User
from apps.accounts.services import AccountService
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
        extra_kwargs = {
            "email": {"validators": []},  # validate_email에서 직접 검증
            "nickname": {"validators": []},  # validate_nickname에서 직접 검증
        }

    def validate_password(self, value):
        return validate_password_strength(value)

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)

            # 유예 기간 만료된 계정이면 삭제 후 허용
            if AccountService.delete_if_expired(user):
                return value

            # 유예 기간 내 탈퇴 예약 상태
            if AccountService.is_in_deletion_grace_period(user):
                raise serializers.ValidationError(
                    "탈퇴 예약된 계정입니다. 기존 비밀번호로 로그인하면 계정이 복구됩니다."
                )

            raise serializers.ValidationError("이미 사용 중인 이메일입니다.")
        except User.DoesNotExist:
            return value

    def validate_nickname(self, value):
        try:
            user = User.objects.get(nickname=value)

            # 유예 기간 만료된 계정이면 삭제 후 허용
            if AccountService.delete_if_expired(user):
                return value

            # 유예 기간 내 탈퇴 예약 상태
            if AccountService.is_in_deletion_grace_period(user):
                raise serializers.ValidationError(
                    "탈퇴 예약된 계정의 닉네임입니다. 잠시 후 다시 시도해주세요."
                )

            raise serializers.ValidationError("이미 사용 중인 닉네임입니다.")
        except User.DoesNotExist:
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
        current_user = self.context["request"].user
        existing = User.objects.filter(nickname=value).exclude(pk=current_user.pk).first()

        if not existing:
            return value

        # 유예 기간 만료된 계정이면 삭제 후 허용
        if AccountService.delete_if_expired(existing):
            return value

        # 유예 기간 내 탈퇴 예약 상태
        if AccountService.is_in_deletion_grace_period(existing):
            raise serializers.ValidationError(
                "탈퇴 예약된 계정의 닉네임입니다. 잠시 후 다시 시도해주세요."
            )

        raise serializers.ValidationError("이미 사용 중인 닉네임입니다.")


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


class EmailVerificationSerializer(serializers.Serializer):
    """이메일 인증 확인"""

    token = serializers.CharField(help_text="이메일로 받은 인증 토큰")


class EmailVerificationResendSerializer(serializers.Serializer):
    """이메일 인증 재전송"""

    email = serializers.EmailField(help_text="가입된 이메일 주소")


class PasswordChangeSerializer(serializers.Serializer):
    """비밀번호 변경 (로그인 상태)"""

    current_password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="현재 비밀번호",
    )
    new_password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="새 비밀번호 (최소 8자, 대소문자, 숫자, 특수문자 각 1개 이상)",
    )
    new_password2 = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="새 비밀번호 확인",
    )

    def validate_new_password(self, value):
        return validate_password_strength(value)


class AccountDeleteSerializer(serializers.Serializer):
    """회원 탈퇴 (비밀번호 확인)"""

    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="현재 비밀번호",
    )


class EmailCheckSerializer(serializers.Serializer):
    """이메일 중복 체크"""

    email = serializers.EmailField(help_text="확인할 이메일 주소")


class NicknameCheckSerializer(serializers.Serializer):
    """닉네임 중복 체크"""

    nickname = serializers.CharField(max_length=50, help_text="확인할 닉네임")


class EmailChangeRequestSerializer(serializers.Serializer):
    """이메일 변경 요청"""

    new_email = serializers.EmailField(help_text="변경할 새 이메일 주소")
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="현재 비밀번호",
    )


class EmailChangeConfirmSerializer(serializers.Serializer):
    """이메일 변경 확인"""

    token = serializers.CharField(help_text="이메일로 받은 인증 토큰")
