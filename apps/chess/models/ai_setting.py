from django.db import models


class AiDifficultySetting(models.Model):
    """AI 난이도 설정 (관리자 조정)"""

    LEVEL_CHOICES = [
        ("easy", "쉬움"),
        ("medium", "중간"),
        ("hard", "어려움"),
    ]

    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, unique=True)
    depth = models.IntegerField(default=0)
    randomness = models.IntegerField(default=4)
    delay_ms = models.IntegerField(default=800)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "ai_difficulty_settings"
        verbose_name = "AI 난이도 설정"
        verbose_name_plural = "AI 난이도 설정"

    def __str__(self):
        return f"{self.level} (depth={self.depth}, randomness={self.randomness}, delay_ms={self.delay_ms})"

    @staticmethod
    def get_config() -> dict[str, dict[str, int]]:
        config: dict[str, dict[str, int]] = {}
        for item in AiDifficultySetting.objects.all():
            config[item.level] = {
                "depth": item.depth,
                "randomness": item.randomness,
                "delay_ms": item.delay_ms,
            }
        return config
