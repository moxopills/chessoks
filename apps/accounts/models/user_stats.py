"""사용자 게임 통계 모델"""

from django.conf import settings
from django.db import models

from apps.accounts.services.model_integrity_service import AccountModelIntegrityService


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
    owned_nickname_colors = models.JSONField(
        default=list,
        blank=True,
        help_text="구매해 보유 중인 닉네임 색상 키 목록",
    )
    owned_profile_borders = models.JSONField(
        default=list,
        blank=True,
        help_text="구매해 보유 중인 프로필 테두리 키 목록",
    )
    season_title = models.CharField(
        max_length=80,
        blank=True,
        default="",
        help_text="활성 시즌 칭호",
    )
    profile_card_frame = models.CharField(
        max_length=40,
        blank=True,
        default="",
        help_text="선택된 프로필 카드 프레임 키",
    )
    owned_season_titles = models.JSONField(
        default=list,
        blank=True,
        help_text="시즌 보상으로 획득한 칭호 목록",
    )
    owned_profile_card_frames = models.JSONField(
        default=list,
        blank=True,
        help_text="시즌 보상으로 획득한 프로필 카드 프레임 목록",
    )
    earned_achievement_keys = models.JSONField(
        default=list,
        blank=True,
        help_text="달성한 업적 키 목록",
    )
    featured_achievement_key = models.CharField(
        max_length=40,
        blank=True,
        default="",
        help_text="대표 업적 키",
    )
    selected_board_skin = models.ForeignKey(
        "accounts.Skin",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        limit_choices_to={"skin_type": "board"},
        help_text="선택된 보드 스킨",
    )
    selected_piece_skin = models.ForeignKey(
        "accounts.Skin",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        limit_choices_to={"skin_type": "pieces"},
        help_text="선택된 기물 스킨",
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
        AccountModelIntegrityService.validate_user_stats(self)
