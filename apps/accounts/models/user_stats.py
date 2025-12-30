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
        ]
        indexes = [
            models.Index(fields=["-rating"], name="stats_rating_idx"),
            models.Index(fields=["-games_played"], name="stats_games_idx"),
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
