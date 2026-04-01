from __future__ import annotations


class SeasonStatService:
    """SeasonStat 계산 로직 전용 서비스."""

    @staticmethod
    def get_win_rate(season_stat) -> float:
        games_played = getattr(season_stat, "games_played", 0) or 0
        if games_played <= 0:
            return 0.0
        wins = getattr(season_stat, "wins", 0) or 0
        return round((wins / games_played) * 100, 1)
