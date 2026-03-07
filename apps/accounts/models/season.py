from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class Season(models.Model):
    """시즌 메타 정보."""

    name = models.CharField(max_length=50)
    start_date = models.DateField(db_index=True)
    end_date = models.DateField(db_index=True)
    is_active = models.BooleanField(default=False, db_index=True)
    is_finalized = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "seasons"
        ordering = ["-start_date"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(end_date__gte=models.F("start_date")),
                name="season_date_range_valid",
            ),
            models.UniqueConstraint(
                fields=["is_active"],
                condition=models.Q(is_active=True),
                name="season_single_active_true",
            ),
        ]
        indexes = [
            models.Index(fields=["is_active", "is_finalized"], name="season_active_final_idx"),
        ]

    def __str__(self) -> str:
        return self.name

    def clean(self):
        super().clean()
        if self.end_date < self.start_date:
            raise ValidationError("시즌 종료일은 시작일보다 빠를 수 없습니다.")


class SeasonStat(models.Model):
    """유저 시즌 통계."""

    season = models.ForeignKey(Season, on_delete=models.CASCADE, related_name="stats")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="season_stats",
    )
    rating = models.IntegerField(default=1200)
    peak_rating = models.IntegerField(default=1200)
    games_played = models.IntegerField(default=0)
    wins = models.IntegerField(default=0)
    losses = models.IntegerField(default=0)
    draws = models.IntegerField(default=0)
    final_rank = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "season_stats"
        unique_together = [("season", "user")]
        indexes = [
            models.Index(fields=["season", "-rating"], name="season_rating_idx"),
            models.Index(fields=["season", "final_rank"], name="season_rank_idx"),
            models.Index(fields=["season", "games_played"], name="season_games_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(rating__gte=0) & models.Q(rating__lte=4000),
                name="season_stats_rating_range",
            ),
            models.CheckConstraint(
                condition=models.Q(games_played__gte=0),
                name="season_stats_games_nonnegative",
            ),
            models.CheckConstraint(
                condition=models.Q(wins__gte=0) & models.Q(losses__gte=0) & models.Q(draws__gte=0),
                name="season_stats_result_nonnegative",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.season_id}:{self.user_id} ({self.rating})"

    @property
    def win_rate(self) -> float:
        if self.games_played <= 0:
            return 0.0
        return round((self.wins / self.games_played) * 100, 1)


class SeasonReward(models.Model):
    """시즌 보상 정의."""

    TYPE_TITLE = "title"
    TYPE_BORDER = "border"
    TYPE_POINTS = "points"
    TYPE_CHOICES = [
        (TYPE_TITLE, "칭호"),
        (TYPE_BORDER, "프로필 카드 프레임"),
        (TYPE_POINTS, "포인트"),
    ]

    season = models.ForeignKey(Season, on_delete=models.CASCADE, related_name="rewards")
    rank_min = models.IntegerField()
    rank_max = models.IntegerField()
    reward_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    reward_value = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "season_rewards"
        ordering = ["rank_min", "id"]
        indexes = [
            models.Index(fields=["season", "rank_min", "rank_max"], name="season_reward_rank_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(rank_min__gte=1) & models.Q(rank_max__gte=models.F("rank_min")),
                name="season_reward_rank_range_valid",
            )
        ]

    def __str__(self) -> str:
        return f"{self.season_id} {self.rank_min}-{self.rank_max} {self.reward_type}"


class UserSeasonReward(models.Model):
    """유저 시즌 보상 지급/수령 기록."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="season_reward_claims",
    )
    season = models.ForeignKey(Season, on_delete=models.CASCADE, related_name="user_rewards")
    reward = models.ForeignKey(SeasonReward, on_delete=models.CASCADE, related_name="user_rewards")
    claimed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_season_rewards"
        unique_together = [("user", "reward")]
        indexes = [
            models.Index(fields=["user", "season", "claimed_at"], name="user_season_claim_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.user_id}:{self.reward_id}:{'claimed' if self.claimed_at else 'pending'}"
