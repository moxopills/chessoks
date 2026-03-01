from django.conf import settings
from django.db import models


class Puzzle(models.Model):
    """체스 퍼즐 원본 데이터"""

    lichess_id = models.CharField(max_length=16, unique=True, null=True, blank=True, db_index=True)
    fen = models.CharField(max_length=120)
    moves = models.JSONField(default=list)
    rating = models.IntegerField(default=1500, db_index=True)
    themes = models.JSONField(default=list)
    game_url = models.URLField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "puzzles"
        ordering = ["-rating", "-id"]
        indexes = [
            models.Index(fields=["rating", "id"], name="puzzle_rating_idx"),
        ]

    def __str__(self) -> str:
        return f"Puzzle#{self.id}({self.lichess_id or 'custom'})"


class DailyPuzzle(models.Model):
    """날짜별 퍼즐 지정"""

    LEVEL_EASY = "easy"
    LEVEL_MEDIUM = "medium"
    LEVEL_HARD = "hard"
    LEVEL_CHOICES = (
        (LEVEL_EASY, "쉬움"),
        (LEVEL_MEDIUM, "중간"),
        (LEVEL_HARD, "어려움"),
    )

    date = models.DateField(db_index=True)
    level = models.CharField(
        max_length=12, choices=LEVEL_CHOICES, default=LEVEL_MEDIUM, db_index=True
    )
    puzzle = models.ForeignKey(Puzzle, on_delete=models.CASCADE, related_name="daily_usages")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "daily_puzzles"
        ordering = ["-date"]
        unique_together = [("date", "level")]
        indexes = [
            models.Index(fields=["date", "level"], name="daily_puzzle_date_level_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.date}({self.level}) -> {self.puzzle_id}"


class UserPuzzleAttempt(models.Model):
    """사용자 일일 퍼즐 시도 기록"""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    daily_puzzle = models.ForeignKey(
        DailyPuzzle, on_delete=models.CASCADE, related_name="user_attempts"
    )
    puzzle = models.ForeignKey(Puzzle, on_delete=models.CASCADE, related_name="user_attempts")

    solved = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    hints_used = models.IntegerField(default=0)
    moves_made = models.JSONField(default=list)

    started_at = models.DateTimeField(auto_now_add=True)
    solved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "user_puzzle_attempts"
        unique_together = [("user", "daily_puzzle")]
        indexes = [
            models.Index(fields=["user", "solved", "solved_at"], name="puzzle_user_solved_idx"),
            models.Index(fields=["daily_puzzle", "user"], name="puzzle_daily_user_idx"),
        ]

    def __str__(self) -> str:
        return f"user={self.user_id}, daily={self.daily_puzzle_id}, solved={self.solved}"
