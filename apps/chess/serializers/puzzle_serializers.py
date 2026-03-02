from rest_framework import serializers


class PuzzleMoveRequestSerializer(serializers.Serializer):
    move = serializers.CharField(max_length=8)
    level = serializers.ChoiceField(
        choices=[("easy", "쉬움"), ("medium", "중간"), ("hard", "어려움")],
        required=False,
    )

    def validate_move(self, value: str) -> str:
        move = (value or "").strip().lower()
        if len(move) < 4:
            raise serializers.ValidationError("수 입력 형식이 올바르지 않습니다. 예: e2e4")
        return move


class PuzzleDailyResponseSerializer(serializers.Serializer):
    date = serializers.DateField()
    level = serializers.ChoiceField(
        choices=[("easy", "쉬움"), ("medium", "중간"), ("hard", "어려움")]
    )
    level_label = serializers.CharField()
    puzzle = serializers.DictField()
    attempt = serializers.DictField(allow_null=True)
    hint_limit = serializers.IntegerField()
    hints_used = serializers.IntegerField()
    remaining_hints = serializers.IntegerField()


class PuzzleMoveResponseSerializer(serializers.Serializer):
    correct = serializers.BooleanField()
    completed = serializers.BooleanField()
    message = serializers.CharField(required=False, allow_blank=True)
    already_solved = serializers.BooleanField(required=False)
    next_move = serializers.CharField(required=False, allow_null=True)
    hint = serializers.CharField(required=False, allow_null=True)


class PuzzleHintResponseSerializer(serializers.Serializer):
    hint_type = serializers.CharField()
    square = serializers.CharField(required=False)
    hints_used = serializers.IntegerField(required=False)
    remaining_hints = serializers.IntegerField(required=False)
    message = serializers.CharField(required=False)


class PuzzleSolutionResponseSerializer(serializers.Serializer):
    moves = serializers.ListField(child=serializers.CharField())
    replay_moves = serializers.ListField(child=serializers.CharField(), required=False)
    steps = serializers.ListField(child=serializers.DictField(), required=False)
    solved = serializers.BooleanField()
    message = serializers.CharField(required=False, allow_blank=True)


class PuzzleStatsResponseSerializer(serializers.Serializer):
    total = serializers.IntegerField()
    solved = serializers.IntegerField()
    solve_rate = serializers.FloatField()
    avg_attempts = serializers.FloatField()


class PuzzleStreakResponseSerializer(serializers.Serializer):
    current_streak = serializers.IntegerField()
    best_streak = serializers.IntegerField()
