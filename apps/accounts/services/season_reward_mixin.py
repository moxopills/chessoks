from __future__ import annotations

from apps.accounts.models import Season, SeasonReward, UserStats
from apps.chess.models import Game


class SeasonRewardMixin:
    @classmethod
    def _ensure_default_rewards(cls, season: Season) -> None:
        if season.rewards.exists():
            return
        SeasonReward.objects.bulk_create(
            [
                SeasonReward(
                    season=season,
                    rank_min=rank_min,
                    rank_max=rank_max,
                    reward_type=reward_type,
                    reward_value=value,
                )
                for rank_min, rank_max, reward_type, value in cls.DEFAULT_REWARDS
            ]
        )

    @staticmethod
    def _resolve_reward_value(season: Season, reward: SeasonReward) -> str:
        value = reward.reward_value or ""
        if "{season}" in value:
            return value.replace("{season}", season.name)
        return value

    @classmethod
    def get_reward_raw_value(cls, *, season: Season, reward: SeasonReward) -> str:
        return cls._resolve_reward_value(season, reward)

    @staticmethod
    def _append_unique(items: list[str], value: str) -> list[str]:
        if not value:
            return items
        if value in items:
            return items
        return [*items, value]

    @classmethod
    def _apply_reward_to_stats(
        cls,
        *,
        season: Season,
        stats: UserStats,
        reward: SeasonReward,
    ) -> str | None:
        value = cls._resolve_reward_value(season, reward)
        if reward.reward_type == SeasonReward.TYPE_POINTS:
            try:
                points = int(value)
            except (TypeError, ValueError):
                return None
            if points <= 0:
                return None
            stats.style_points += points
            return f"포인트 +{points}"

        if reward.reward_type == SeasonReward.TYPE_TITLE:
            titles = list(stats.owned_season_titles or [])
            stats.owned_season_titles = cls._append_unique(titles, value)
            stats.season_title = value
            return f"칭호 {value}"

        if reward.reward_type == SeasonReward.TYPE_BORDER:
            frames = list(stats.owned_profile_card_frames or [])
            stats.owned_profile_card_frames = cls._append_unique(frames, value)
            stats.profile_card_frame = value
            return f"프레임 {value}"

        return None

    @classmethod
    def get_reward_display_value(cls, *, season: Season, reward: SeasonReward) -> str:
        value = cls._resolve_reward_value(season, reward)
        if reward.reward_type == SeasonReward.TYPE_POINTS:
            try:
                return f"{int(value):,}P"
            except (TypeError, ValueError):
                return str(value)
        if reward.reward_type == SeasonReward.TYPE_BORDER:
            return cls.FRAME_LABELS.get(value, value)
        return value

    @classmethod
    def get_reward_summary_payload(cls, *, season: Season, reward: SeasonReward) -> dict:
        return {
            "id": reward.id,
            "rank_min": reward.rank_min,
            "rank_max": reward.rank_max,
            "reward_type": reward.reward_type,
            "reward_type_label": reward.get_reward_type_display(),
            "reward_value": cls.get_reward_display_value(season=season, reward=reward),
            "reward_key": cls._resolve_reward_value(season, reward),
        }

    @classmethod
    def _result_tuple(cls, game_result: str) -> tuple[str, str, float, float]:
        if game_result in [Game.Status.WHITE_WIN, Game.Status.CHECKMATE_WHITE]:
            return "win", "loss", 1.0, 0.0
        if game_result in [Game.Status.BLACK_WIN, Game.Status.CHECKMATE_BLACK]:
            return "loss", "win", 0.0, 1.0
        if game_result in [Game.Status.TIMEOUT_BLACK, Game.Status.RESIGNATION_BLACK]:
            return "win", "loss", 1.0, 0.0
        if game_result in [Game.Status.TIMEOUT_WHITE, Game.Status.RESIGNATION_WHITE]:
            return "loss", "win", 0.0, 1.0
        return "draw", "draw", 0.5, 0.5
