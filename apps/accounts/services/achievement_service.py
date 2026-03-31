"""프로필 업적 서비스."""

from __future__ import annotations

from dataclasses import dataclass

from django.core.cache import cache
from django.db import transaction

from apps.accounts.models import Friend, User, UserStats
from apps.accounts.models.skin import SkinPointLog, UserSkin
from apps.chess.services.puzzle_service import PuzzleService


@dataclass(frozen=True)
class AchievementDefinition:
    key: str
    title: str
    description: str
    icon: str
    tone: str
    target: int
    metric: str
    progress_label: str
    reward_points: int


class AchievementService:
    """프로필 업적 계산 서비스.

    새 모델 없이 기존 통계/퍼즐/친구 데이터를 조합해 업적을 계산한다.
    프로필 화면에서만 쓰이는 값이라 짧은 TTL 캐시로 반복 계산 비용을 줄인다.
    """

    CACHE_TTL_SECONDS = 60 * 3

    DEFINITIONS = (
        AchievementDefinition(
            key="first_win",
            title="첫 승리",
            description="처음으로 승리를 기록했습니다.",
            icon="♟️",
            tone="success",
            target=1,
            metric="wins",
            progress_label="승리",
            reward_points=5,
        ),
        AchievementDefinition(
            key="regular_player",
            title="체스 단골",
            description="누적 25판을 달성했습니다.",
            icon="🎯",
            tone="info",
            target=25,
            metric="games_played",
            progress_label="판",
            reward_points=5,
        ),
        AchievementDefinition(
            key="win_streak",
            title="연승 시동",
            description="연승 3회를 달성했습니다.",
            icon="🔥",
            tone="danger",
            target=3,
            metric="win_streak",
            progress_label="연승",
            reward_points=7,
        ),
        AchievementDefinition(
            key="ranked_rookie",
            title="배치 완료",
            description="경쟁전 5판을 채워 랭킹이 열렸습니다.",
            icon="🏅",
            tone="warning",
            target=5,
            metric="competitive_games_played",
            progress_label="경쟁전",
            reward_points=6,
        ),
        AchievementDefinition(
            key="puzzle_starter",
            title="퍼즐 입문",
            description="퍼즐을 1개 이상 해결했습니다.",
            icon="🧩",
            tone="accent",
            target=1,
            metric="puzzle_solved",
            progress_label="해결",
            reward_points=5,
        ),
        AchievementDefinition(
            key="puzzle_focus",
            title="퍼즐 집중력",
            description="퍼즐 연속 3일 해결을 달성했습니다.",
            icon="💡",
            tone="info",
            target=3,
            metric="puzzle_best_streak",
            progress_label="연속",
            reward_points=8,
        ),
        AchievementDefinition(
            key="social_knight",
            title="친구 많은 기사",
            description="친구 3명을 달성했습니다.",
            icon="🤝",
            tone="success",
            target=3,
            metric="friend_count",
            progress_label="친구",
            reward_points=6,
        ),
        AchievementDefinition(
            key="style_collector",
            title="스타일 수집가",
            description="커스터마이징 아이템 5개를 모았습니다.",
            icon="🎨",
            tone="accent",
            target=5,
            metric="customization_owned",
            progress_label="보유",
            reward_points=8,
        ),
        AchievementDefinition(
            key="season_reward",
            title="시즌 수상자",
            description="시즌 보상을 1개 이상 획득했습니다.",
            icon="🏆",
            tone="warning",
            target=1,
            metric="season_rewards_owned",
            progress_label="보상",
            reward_points=10,
        ),
    )
    DEFINITION_MAP = {definition.key: definition for definition in DEFINITIONS}

    @classmethod
    def get_profile_achievements(cls, user: User) -> list[dict]:
        stats = cls._get_stats(user)
        cache_key = cls._cache_key(user.id, stats=stats)
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        metrics = cls._collect_metrics(user, stats=stats)
        metrics["earned_keys"] = list(stats.earned_achievement_keys or [])
        payload = cls._build_payload(metrics)
        cache.set(cache_key, payload, cls.CACHE_TTL_SECONDS)
        return payload

    @staticmethod
    def _get_stats(user: User) -> UserStats:
        stats = getattr(user, "stats", None)
        if stats is not None:
            return stats
        return UserStats.objects.only(
            "id",
            "user_id",
            "games_played",
            "games_won",
            "competitive_games_played",
            "win_streak",
            "style_points",
            "owned_nickname_colors",
            "owned_profile_borders",
            "owned_season_titles",
            "owned_profile_card_frames",
            "selected_board_skin_id",
            "selected_piece_skin_id",
            "updated_at",
        ).get(user_id=user.id)

    @classmethod
    def _cache_key(cls, user_id: int, *, stats: UserStats) -> str:
        version = int(stats.updated_at.timestamp()) if stats.updated_at else 0
        return f"profile_achievements:{user_id}:v{version}"

    @classmethod
    def _collect_metrics(cls, user: User, *, stats: UserStats) -> dict[str, int]:
        puzzle_stats = PuzzleService.get_stats(user=user)
        puzzle_streak = PuzzleService.get_streak(user=user)

        return {
            "wins": stats.games_won,
            "games_played": stats.games_played,
            "win_streak": stats.win_streak,
            "competitive_games_played": stats.competitive_games_played,
            "puzzle_solved": int(puzzle_stats.get("solved") or 0),
            "puzzle_best_streak": int(puzzle_streak.get("best_streak") or 0),
            "friend_count": Friend.objects.filter(user_id=user.id).count(),
            "customization_owned": cls._count_owned_customizations(user=user, stats=stats),
            "season_rewards_owned": cls._count_owned_season_rewards(stats),
        }

    @staticmethod
    def _count_owned_customizations(*, user: User, stats: UserStats) -> int:
        owned_skin_count = UserSkin.objects.filter(user_id=user.id).count()
        return (
            len(stats.owned_nickname_colors or [])
            + len(stats.owned_profile_borders or [])
            + owned_skin_count
        )

    @staticmethod
    def _count_owned_season_rewards(stats: UserStats) -> int:
        return len(stats.owned_season_titles or []) + len(stats.owned_profile_card_frames or [])

    @classmethod
    def _build_payload(cls, metrics: dict[str, int]) -> list[dict]:
        earned_keys = set(metrics.get("earned_keys", []))
        achievements: list[dict] = []
        for definition in cls.DEFINITIONS:
            value = int(metrics.get(definition.metric, 0))
            progress = (
                min(100, int((value / definition.target) * 100)) if definition.target else 100
            )
            is_earned = definition.key in earned_keys or value >= definition.target
            achievements.append(
                {
                    "key": definition.key,
                    "title": definition.title,
                    "description": definition.description,
                    "icon": definition.icon,
                    "tone": definition.tone,
                    "is_earned": is_earned,
                    "progress": 100 if is_earned else progress,
                    "current_value": value,
                    "target_value": definition.target,
                    "progress_text": (
                        f"{definition.target}/{definition.target} {definition.progress_label}"
                        if is_earned
                        else f"{min(value, definition.target)}/{definition.target} {definition.progress_label}"
                    ),
                    "reward_points": definition.reward_points,
                }
            )

        return sorted(
            achievements,
            key=lambda item: (
                0 if item["is_earned"] else 1,
                -item["progress"],
                item["title"],
            ),
        )

    @classmethod
    def get_featured_achievement(cls, user: User) -> dict | None:
        stats = cls._get_stats(user)
        return cls.get_featured_achievement_for_stats(stats)

    @classmethod
    def get_featured_achievement_for_stats(cls, stats: UserStats | None) -> dict | None:
        if stats is None:
            return None
        definition = cls.DEFINITION_MAP.get((stats.featured_achievement_key or "").strip())
        if definition is None:
            return None
        return {
            "key": definition.key,
            "title": definition.title,
            "icon": definition.icon,
            "tone": definition.tone,
        }

    @classmethod
    @transaction.atomic
    def sync_rewards_for_user(cls, user_id: int) -> list[dict]:
        stats = UserStats.objects.select_for_update().get(user_id=user_id)
        cache_key_before = cls._cache_key(user_id, stats=stats)
        user = (
            User.objects.select_related(
                "stats", "stats__selected_board_skin", "stats__selected_piece_skin"
            )
            .only(
                "id",
                "stats__id",
                "stats__games_played",
                "stats__games_won",
                "stats__competitive_games_played",
                "stats__win_streak",
                "stats__owned_nickname_colors",
                "stats__owned_profile_borders",
                "stats__owned_season_titles",
                "stats__owned_profile_card_frames",
                "stats__earned_achievement_keys",
                "stats__featured_achievement_key",
                "stats__selected_board_skin_id",
                "stats__selected_piece_skin_id",
                "stats__updated_at",
            )
            .get(pk=user_id)
        )
        metrics = cls._collect_metrics(user, stats=stats)
        earned_keys = {
            item for item in (stats.earned_achievement_keys or []) if item in cls.DEFINITION_MAP
        }
        newly_earned: list[AchievementDefinition] = []
        for definition in cls.DEFINITIONS:
            if definition.key in earned_keys:
                continue
            if int(metrics.get(definition.metric, 0)) >= definition.target:
                earned_keys.add(definition.key)
                newly_earned.append(definition)

        if not newly_earned and (stats.featured_achievement_key or "") in earned_keys:
            return []

        reward_payloads: list[dict] = []
        for definition in newly_earned:
            reference_id = f"achievement:{definition.key}"
            if SkinPointLog.objects.filter(
                user_id=user_id,
                reason=SkinPointLog.Reason.ACHIEVEMENT_REWARD,
                reference_id=reference_id,
            ).exists():
                continue
            stats.style_points += definition.reward_points
            reward_payloads.append(
                {
                    "key": definition.key,
                    "title": definition.title,
                    "reward_points": definition.reward_points,
                }
            )
            SkinPointLog.objects.create(
                user_id=user_id,
                amount=definition.reward_points,
                balance=stats.style_points,
                reason=SkinPointLog.Reason.ACHIEVEMENT_REWARD,
                reference_id=reference_id,
            )

        stats.earned_achievement_keys = cls._sort_earned_keys(earned_keys)
        stats.featured_achievement_key = cls._resolve_featured_key(
            current_key=stats.featured_achievement_key,
            earned_keys=stats.earned_achievement_keys,
            newly_earned=[definition.key for definition in newly_earned],
        )
        update_fields = ["earned_achievement_keys", "featured_achievement_key"]
        if reward_payloads:
            update_fields.append("style_points")
        stats.save(update_fields=update_fields)
        cache.delete(cache_key_before)
        cache.delete(cls._cache_key(user_id, stats=stats))
        cache.delete(f"user_profile:{user_id}:public")
        cache.delete(f"user_profile_{user_id}")
        return reward_payloads

    @classmethod
    def sync_rewards_for_users(cls, user_ids: list[int]) -> None:
        for user_id in {int(user_id) for user_id in user_ids if user_id}:
            cls.sync_rewards_for_user(user_id)

    @classmethod
    def _resolve_featured_key(
        cls,
        *,
        current_key: str,
        earned_keys: list[str],
        newly_earned: list[str],
    ) -> str:
        if newly_earned:
            return newly_earned[-1]
        if current_key and current_key in earned_keys:
            return current_key
        return earned_keys[0] if earned_keys else ""

    @classmethod
    def _sort_earned_keys(cls, keys: set[str]) -> list[str]:
        order = {definition.key: index for index, definition in enumerate(cls.DEFINITIONS)}
        return sorted(keys, key=lambda key: order.get(key, 999))
