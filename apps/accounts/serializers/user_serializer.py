from rest_framework import serializers

from apps.accounts.models import User
from apps.accounts.utils.validators import validate_password_strength
from apps.chess.serializers import GameHistorySerializer


class UserStatsSerializer(serializers.Serializer):
    """사용자 게임 통계 (읽기 전용)"""

    rating = serializers.IntegerField(read_only=True)
    games_played = serializers.IntegerField(read_only=True)
    games_won = serializers.IntegerField(read_only=True)
    games_lost = serializers.IntegerField(read_only=True)
    games_draw = serializers.IntegerField(read_only=True)
    rank_tier = serializers.CharField(source="rank_tier", read_only=True)
    win_rate = serializers.FloatField(read_only=True)


class UserSerializer(serializers.ModelSerializer):
    """사용자 정보 조회용 Serializer"""

    stats = UserStatsSerializer(read_only=True)
    is_muted = serializers.SerializerMethodField()
    is_suspended = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "nickname",
            "avatar_url",
            "bio",
            "created_at",
            "suspended_until",
            "suspension_reason",
            "muted_until",
            "mute_reason",
            "is_muted",
            "is_suspended",
            "stats",
        )
        read_only_fields = (
            "id",
            "created_at",
        )

    def get_is_muted(self, obj):
        return obj.is_muted

    def get_is_suspended(self, obj):
        return obj.is_suspended


class PublicUserSerializer(serializers.ModelSerializer):
    """공개 사용자 정보 Serializer (이메일 제외)"""

    stats = UserStatsSerializer(read_only=True)

    class Meta:
        model = User
        fields = (
            "id",
            "nickname",
            "avatar_url",
            "bio",
            "created_at",
            "stats",
        )


class LeaderboardEntrySerializer(serializers.Serializer):
    """랭킹 보드 항목"""

    id = serializers.IntegerField(read_only=True)
    nickname = serializers.CharField(read_only=True)
    avatar_url = serializers.URLField(read_only=True, allow_null=True)
    rating = serializers.IntegerField(source="stats.rating", read_only=True)
    games_played = serializers.IntegerField(source="stats.games_played", read_only=True)
    games_won = serializers.IntegerField(source="stats.games_won", read_only=True)
    games_draw = serializers.IntegerField(source="stats.games_draw", read_only=True)
    games_lost = serializers.IntegerField(source="stats.games_lost", read_only=True)
    rank_tier = serializers.CharField(source="stats.rank_tier", read_only=True)
    rank = serializers.IntegerField(read_only=True)


class MyRankSerializer(serializers.Serializer):
    """내 랭킹 정보 (페이지네이션 응답 내 포함용)"""

    id = serializers.IntegerField()
    nickname = serializers.CharField()
    avatar_url = serializers.URLField(allow_null=True)
    rating = serializers.IntegerField()
    games_played = serializers.IntegerField()
    games_won = serializers.IntegerField()
    games_draw = serializers.IntegerField()
    games_lost = serializers.IntegerField()
    rank_tier = serializers.CharField()
    rank = serializers.IntegerField()


class LeaderboardResponseSerializer(serializers.Serializer):
    """랭킹 보드 페이지네이션 응답"""

    count = serializers.IntegerField(help_text="전체 유저 수")
    total_pages = serializers.IntegerField(help_text="전체 페이지 수")
    current_page = serializers.IntegerField(help_text="현재 페이지")
    next = serializers.URLField(allow_null=True, help_text="다음 페이지 URL")
    previous = serializers.URLField(allow_null=True, help_text="이전 페이지 URL")
    results = LeaderboardEntrySerializer(many=True, help_text="랭킹 목록")
    my_rank = MyRankSerializer(allow_null=True, help_text="내 랭킹 (로그인 시)")


class OpponentSummarySerializer(serializers.Serializer):
    """상대 전적 요약 (내 기준)"""

    total = serializers.IntegerField()
    wins = serializers.IntegerField()
    losses = serializers.IntegerField()
    draws = serializers.IntegerField()


class OpponentProfileSerializer(serializers.Serializer):
    """상대 프로필 + 최근 전적"""

    user = PublicUserSerializer()
    recent_games = GameHistorySerializer(many=True)
    vs_summary = OpponentSummarySerializer(allow_null=True)
    friend_status = serializers.DictField(required=False)


class DashboardSummarySerializer(UserStatsSerializer):
    """대시보드 요약 (UserStatsSerializer + rank_tier)"""

    rank_tier = serializers.CharField(read_only=True)


class DashboardSerializer(serializers.Serializer):
    user = PublicUserSerializer()
    summary = DashboardSummarySerializer()
    recent_games = GameHistorySerializer(many=True)


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
            "email": {"validators": []},  # 서비스에서 검증
            "nickname": {"validators": []},  # 서비스에서 검증
        }

    def validate_password(self, value):
        return validate_password_strength(value)

    def validate_nickname(self, value):
        value = value.strip()
        if len(value) < 2:
            raise serializers.ValidationError("닉네임은 최소 2자 이상이어야 합니다.")
        return value

    def create(self, validated_data):
        validated_data.pop("password2")
        user = User.objects.create_user(**validated_data)
        return user


class SignupEmailRequestSerializer(serializers.Serializer):
    """회원가입 이메일 인증 요청"""

    email = serializers.EmailField(help_text="회원가입 이메일")


class SignupEmailConfirmSerializer(serializers.Serializer):
    """회원가입 이메일 인증 확인"""

    email = serializers.EmailField(help_text="회원가입 이메일")
    code = serializers.CharField(help_text="이메일로 받은 인증 코드")


class ProfileUpdateSerializer(serializers.ModelSerializer):
    """프로필 수정용 Serializer"""

    class Meta:
        model = User
        fields = ("nickname", "bio", "avatar_url")
        extra_kwargs = {
            "nickname": {"validators": []},  # 서비스에서 검증
        }

    def validate_nickname(self, value):
        value = value.strip()
        if len(value) < 2:
            raise serializers.ValidationError("닉네임은 최소 2자 이상이어야 합니다.")
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    """비밀번호 재설정 요청"""

    email = serializers.EmailField(help_text="가입된 이메일 주소")


class PasswordResetConfirmSerializer(serializers.Serializer):
    """비밀번호 재설정 확인"""

    code = serializers.CharField(min_length=6, max_length=6, help_text="이메일로 받은 인증번호")
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

    code = serializers.CharField(min_length=6, max_length=6, help_text="이메일로 받은 인증번호")
