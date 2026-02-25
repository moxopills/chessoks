"""사용자 게임 통계 모델"""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class UserStats(models.Model):
    """사용자 게임 통계 - User 모델과 1:1 관계"""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="stats",
        help_text="연결된 사용자",
    )

    rating = models.IntegerField(default=1200, help_text="ELO 레이팅 시스템")
    games_played = models.IntegerField(default=0, help_text="총 게임 수")
    games_won = models.IntegerField(default=0, help_text="승리 수")
    games_lost = models.IntegerField(default=0, help_text="패배 수")
    games_draw = models.IntegerField(default=0, help_text="무승부 수")
    competitive_games_played = models.IntegerField(default=0, help_text="경쟁전 게임 수")
    competitive_won = models.IntegerField(default=0, help_text="경쟁전 승리 수")
    competitive_lost = models.IntegerField(default=0, help_text="경쟁전 패배 수")
    competitive_draw = models.IntegerField(default=0, help_text="경쟁전 무승부 수")
    win_streak = models.IntegerField(default=0, help_text="연승 수")
    lose_streak = models.IntegerField(default=0, help_text="연패 수")
    style_points = models.IntegerField(default=0, help_text="커스터마이징 포인트")
    nickname_color = models.CharField(
        max_length=20, blank=True, default="", help_text="닉네임 색상 키"
    )
    profile_border = models.CharField(
        max_length=20, blank=True, default="", help_text="프로필 테두리 키"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_stats"
        verbose_name = "사용자 통계"
        verbose_name_plural = "사용자 통계"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(rating__gte=0) & models.Q(rating__lte=4000),
                name="stats_rating_range",
            ),
            models.CheckConstraint(
                condition=models.Q(games_played__gte=0),
                name="stats_games_played_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(games_won__gte=0),
                name="stats_games_won_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(games_lost__gte=0),
                name="stats_games_lost_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(games_draw__gte=0),
                name="stats_games_draw_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(competitive_games_played__gte=0),
                name="stats_competitive_games_played_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(competitive_won__gte=0),
                name="stats_competitive_won_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(competitive_lost__gte=0),
                name="stats_competitive_lost_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(competitive_draw__gte=0),
                name="stats_competitive_draw_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(win_streak__gte=0),
                name="stats_win_streak_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(lose_streak__gte=0),
                name="stats_lose_streak_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(style_points__gte=0),
                name="stats_style_points_positive",
            ),
        ]
        indexes = [
            models.Index(fields=["-rating", "-games_played"], name="stats_ranking_idx"),
        ]

    def __str__(self):
        return f"{self.user.nickname} - Rating: {self.rating}"

    def clean(self):
        super().clean()
        if self.rating < 0 or self.rating > 4000:
            raise ValidationError("레이팅은 0-4000 사이여야 합니다")
        if self.games_played < 0:
            raise ValidationError("게임 수는 음수가 될 수 없습니다")

    @property
    def win_rate(self):
        """승률 계산"""
        if self.games_played == 0:
            return 0
        return round((self.games_won / self.games_played) * 100, 2)

    @property
    def rank_tier(self):
        """레이팅 구간 기반 등급"""
        if self.competitive_games_played < 5:
            return "Unranked"
        rating = self.rating
        if rating >= 3500:
            return "Master"
        if rating >= 2700:
            return "Expert"
        if rating >= 2100:
            return "Advanced"
        if rating >= 1700:
            return "Intermediate"
        if rating >= 1200:
            return "Junior"
        return "Beginner"

    @property
    def unlocked_nickname_colors(self):
        unlocks = [{"key": "", "label": "기본", "cost": 0}]
        if self.style_points >= 100:
            unlocks.append({"key": "mint", "label": "민트", "cost": 100})
        if self.style_points >= 250:
            unlocks.append({"key": "sunset", "label": "선셋", "cost": 250})
        if self.style_points >= 450:
            unlocks.append({"key": "gold", "label": "골드", "cost": 450})
        return unlocks

    @property
    def unlocked_profile_borders(self):
        unlocks = [{"key": "", "label": "기본", "cost": 0}]
        if self.style_points >= 120:
            unlocks.append({"key": "mint_ring", "label": "민트 링", "cost": 120})
        if self.style_points >= 300:
            unlocks.append({"key": "royal_ring", "label": "로열 링", "cost": 300})
        if self.style_points >= 500:
            unlocks.append({"key": "champion_ring", "label": "챔피언 링", "cost": 500})
        return unlocks
