from __future__ import annotations

from apps.chess.models import AiDifficultySetting


class AiSettingService:
    """AI 난이도 설정 조회 서비스."""

    @staticmethod
    def get_config() -> dict[str, dict[str, int]]:
        return {
            item.level: {
                "depth": item.depth,
                "randomness": item.randomness,
                "delay_ms": item.delay_ms,
            }
            for item in AiDifficultySetting.objects.all()
        }
