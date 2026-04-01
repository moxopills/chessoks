from __future__ import annotations

from django.core.exceptions import ValidationError


class AccountModelIntegrityService:
    """accounts 모델 무결성 검증 서비스."""

    @staticmethod
    def validate_user_stats(stats) -> None:
        if stats.rating < 0 or stats.rating > 4000:
            raise ValidationError("레이팅은 0-4000 사이여야 합니다")
        if stats.games_played < 0:
            raise ValidationError("게임 수는 음수가 될 수 없습니다")

    @staticmethod
    def validate_season(season) -> None:
        if season.end_date < season.start_date:
            raise ValidationError("시즌 종료일은 시작일보다 빠를 수 없습니다.")
