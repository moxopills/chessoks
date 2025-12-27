from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """커스텀 유저 모델 - 체스 게임 통계 및 프로필 포함"""

    # 이메일 (필수)
    email = models.EmailField(
        max_length=100,
        unique=True,
        null=True,
        db_index=True,
    )

    # 닉네임 (필수)
    nickname = models.CharField(max_length=50, unique=True, help_text="게임 내 표시 이름")

    # 비밀번호 (필수)
    password = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        db_index=True,
    )

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

    class Meta:
        db_table = "users"
        verbose_name = "사용자"
        verbose_name_plural = "사용자"
        ordering = ["-rating", "-created_at"]

    def __str__(self):
        return f"{self.nickname} (Rating: {self.rating})"

    @property
    def win_rate(self):
        """승률 계산"""
        if self.games_played == 0:
            return 0
        return round((self.games_won / self.games_played) * 100, 2)

    def update_stats(self, result):
        """게임 결과에 따라 통계 업데이트

        Args:
            result (str): 'win', 'loss', 'draw'
        """
        self.games_played += 1
        if result == "win":
            self.games_won += 1
        elif result == "loss":
            self.games_lost += 1
        elif result == "draw":
            self.games_draw += 1
        self.save()

    def update_rating(self, opponent_rating, result, k_factor=32):
        """ELO 레이팅 업데이트

        Args:
            opponent_rating (int): 상대방 레이팅
            result (float): 1.0 (승리), 0.5 (무승부), 0.0 (패배)
            k_factor (int): K-factor (기본값 32)
        """
        expected = 1 / (1 + 10 ** ((opponent_rating - self.rating) / 400))
        self.rating = round(self.rating + k_factor * (result - expected))
        self.save()
