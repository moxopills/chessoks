from django.conf import settings
from django.db import models


class Skin(models.Model):
    class SkinType(models.TextChoices):
        BOARD = "board", "보드"
        PIECES = "pieces", "기물"

    name = models.CharField(max_length=50)
    skin_type = models.CharField(max_length=10, choices=SkinType.choices)
    price = models.IntegerField(default=0)
    css_class = models.CharField(max_length=50)
    preview_image = models.URLField(blank=True)
    description = models.TextField(blank=True)
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    sort_order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "skins"
        ordering = ["skin_type", "sort_order", "price", "id"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(price__gte=0),
                name="skin_price_non_negative",
            ),
            models.UniqueConstraint(
                fields=["skin_type", "css_class"],
                name="skin_type_css_unique",
            ),
        ]
        indexes = [
            models.Index(
                fields=["skin_type", "is_active", "sort_order"], name="skin_type_active_idx"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.get_skin_type_display()} - {self.name}"


class UserSkin(models.Model):
    class AcquireMethod(models.TextChoices):
        PURCHASE = "purchase", "구매"
        REWARD = "reward", "보상"
        SYSTEM = "system", "기본 제공"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="owned_skins",
    )
    skin = models.ForeignKey(Skin, on_delete=models.CASCADE, related_name="owners")
    acquired_at = models.DateTimeField(auto_now_add=True)
    acquired_method = models.CharField(
        max_length=20, choices=AcquireMethod.choices, default=AcquireMethod.PURCHASE
    )

    class Meta:
        db_table = "user_skins"
        constraints = [
            models.UniqueConstraint(fields=["user", "skin"], name="user_skin_unique"),
        ]
        indexes = [
            models.Index(fields=["user", "-acquired_at"], name="user_skin_recent_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.user_id}:{self.skin_id}"


class SkinPointLog(models.Model):
    class Reason(models.TextChoices):
        GAME_WIN = "game_win", "게임 승리"
        GAME_LOSS = "game_loss", "게임 패배"
        GAME_DRAW = "game_draw", "게임 무승부"
        SKIN_PURCHASE = "skin_purchase", "스킨 구매"
        PUZZLE_SOLVE = "puzzle_solve", "퍼즐 클리어"
        SEASON_REWARD = "season_reward", "시즌 보상"
        ADJUST = "adjust", "운영자 조정"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="skin_point_logs",
    )
    amount = models.IntegerField()
    balance = models.IntegerField()
    reason = models.CharField(max_length=50, choices=Reason.choices)
    reference_id = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "skin_point_logs"
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["user", "-created_at"], name="skin_point_user_recent_idx"),
            models.Index(fields=["reason", "-created_at"], name="skin_point_reason_recent_idx"),
        ]

    def __str__(self) -> str:
        sign = "+" if self.amount >= 0 else ""
        return f"{self.user_id}:{sign}{self.amount}({self.reason})"
