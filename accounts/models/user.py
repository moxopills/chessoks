from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.exceptions import ValidationError
from django.db import models


class UserManager(BaseUserManager):
    """커스텀 유저 매니저"""

    def create_user(self, username, email, nickname, password=None, **extra_fields):
        """일반 유저 생성"""
        if not email:
            raise ValueError("이메일은 필수입니다")
        if not nickname:
            raise ValueError("닉네임은 필수입니다")

        email = self.normalize_email(email)
        user = self.model(username=username, email=email, nickname=nickname, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, nickname, password=None, **extra_fields):
        """슈퍼유저 생성"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(username, email, nickname, password, **extra_fields)

    def top_players(self, limit=10):
        """상위 레이팅 플레이어"""
        return self.filter(is_active=True).order_by("-rating")[:limit]

    def active_players(self):
        """활성 플레이어"""
        return self.filter(is_active=True)


class User(AbstractUser):
    """커스텀 유저 모델 - 체스 게임 통계 및 프로필 포함

    Note: password 필드는 AbstractUser에 이미 포함되어 있음
    """

    # 이메일 (필수, AbstractUser의 email을 override)
    email = models.EmailField(
        unique=True,
        db_index=True,
        help_text="이메일 주소",
    )

    # 닉네임 (필수)
    nickname = models.CharField(max_length=50, unique=True, help_text="게임 내 표시 이름")

    # 체스 레이팅
    rating = models.IntegerField(default=1200, help_text="ELO 레이팅 시스템")

    # 게임 통계
    games_played = models.IntegerField(default=0, help_text="총 게임 수")
    games_won = models.IntegerField(default=0, help_text="승리 수")
    games_lost = models.IntegerField(default=0, help_text="패배 수")
    games_draw = models.IntegerField(default=0, help_text="무승부 수")

    # 프로필 이미지 (S3 URL)
    avatar_url = models.URLField(
        max_length=500, blank=True, null=True, help_text="S3 프로필 사진 URL"
    )

    # 자기소개
    bio = models.TextField(blank=True, help_text="자기소개")

    # 타임스탬프
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email", "nickname"]

    class Meta:
        db_table = "users"
        verbose_name = "사용자"
        verbose_name_plural = "사용자"
        ordering = ["-rating", "-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(rating__gte=0) & models.Q(rating__lte=4000),
                name="rating_range",
            ),
            models.CheckConstraint(
                condition=models.Q(games_played__gte=0), name="games_played_positive"
            ),
        ]

    def __str__(self):
        return f"{self.nickname} (Rating: {self.rating})"

    def clean(self):
        """모델 검증"""
        super().clean()
        if self.rating < 0 or self.rating > 4000:
            raise ValidationError("레이팅은 0-4000 사이여야 합니다")
        if self.games_played < 0:
            raise ValidationError("게임 수는 음수가 될 수 없습니다")

    @property
    def win_rate(self):
        """승률 계산 (읽기 전용 property)"""
        if self.games_played == 0:
            return 0
        return round((self.games_won / self.games_played) * 100, 2)
