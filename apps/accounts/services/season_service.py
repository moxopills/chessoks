from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date

from django.core.cache import cache
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from rest_framework.exceptions import ValidationError

from apps.accounts.models import Season, SeasonReward, SeasonStat, UserSeasonReward, UserStats
from apps.chess.models import Game
from apps.chess.services.rating_service import RatingService
from apps.notifications.services import NotificationService


@dataclass(frozen=True)
class SeasonPage:
    count: int | None
    page: int
    page_size: int
    total_pages: int | None
    has_next: bool
    results: list[dict]


class SeasonService:
    """시즌 래더 서비스."""

    BASE_RATING = 1200
    MIN_GAMES_FOR_RANK = 10
    CACHE_TTL = 60
    MAX_PAGE_SIZE = 100
    CACHE_VERSION_KEY = "season_leaderboard_version"

    DEFAULT_REWARDS = (
        (1, 1, SeasonReward.TYPE_TITLE, "👑 챔피언"),
        (1, 1, SeasonReward.TYPE_POINTS, "1000"),
        (1, 1, SeasonReward.TYPE_BORDER, "gold"),
        (2, 3, SeasonReward.TYPE_TITLE, "🥈 그랜드마스터"),
        (2, 3, SeasonReward.TYPE_POINTS, "500"),
        (2, 3, SeasonReward.TYPE_BORDER, "silver"),
        (4, 10, SeasonReward.TYPE_TITLE, "🥉 마스터"),
        (4, 10, SeasonReward.TYPE_POINTS, "300"),
        (4, 10, SeasonReward.TYPE_BORDER, "bronze"),
        (11, 50, SeasonReward.TYPE_POINTS, "100"),
        (51, 100, SeasonReward.TYPE_POINTS, "50"),
    )

    @staticmethod
    def _month_range(today: date) -> tuple[date, date]:
        _, last_day = calendar.monthrange(today.year, today.month)
        return date(today.year, today.month, 1), date(today.year, today.month, last_day)

    @staticmethod
    def _season_name(target: date) -> str:
        return f"{target.year}년 {target.month:02d}월 시즌"

    @classmethod
    def get_cache_version(cls) -> int:
        current = cache.get(cls.CACHE_VERSION_KEY)
        if current is None:
            cache.set(cls.CACHE_VERSION_KEY, 1, None)
            return 1
        return int(current)

    @classmethod
    def invalidate_leaderboard_cache(cls) -> None:
        try:
            cache.incr(cls.CACHE_VERSION_KEY)
        except ValueError:
            cache.set(cls.CACHE_VERSION_KEY, 1, None)

    @classmethod
    @transaction.atomic
    def get_or_create_current_season(cls, today: date | None = None) -> Season:
        today = today or timezone.localdate()
        active_list = list(
            Season.objects.select_for_update()
            .filter(is_active=True, start_date__lte=today, end_date__gte=today)
            .order_by("id")
        )
        active = active_list[0] if active_list else None
        if len(active_list) > 1:
            Season.objects.filter(id__in=[item.id for item in active_list[1:]]).update(
                is_active=False
            )
        if active:
            if not active.rewards.exists():
                cls._ensure_default_rewards(active)
            return active

        start_date, end_date = cls._month_range(today)
        season, created = Season.objects.select_for_update().get_or_create(
            start_date=start_date,
            defaults={
                "name": cls._season_name(start_date),
                "end_date": end_date,
                "is_active": True,
                "is_finalized": False,
            },
        )
        if created:
            cls._ensure_default_rewards(season)
        elif not season.is_active:
            Season.objects.filter(is_active=True).update(is_active=False)
            season.is_active = True
            season.is_finalized = False
            season.save(update_fields=["is_active", "is_finalized"])
            if not season.rewards.exists():
                cls._ensure_default_rewards(season)
        return season

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

    @classmethod
    @transaction.atomic
    def update_after_competitive_game(
        cls,
        *,
        white_user_id: int,
        black_user_id: int,
        game_result: str,
    ) -> None:
        season = cls.get_or_create_current_season()
        white_stat, _ = SeasonStat.objects.select_for_update().get_or_create(
            season=season, user_id=white_user_id, defaults={"rating": cls.BASE_RATING}
        )
        black_stat, _ = SeasonStat.objects.select_for_update().get_or_create(
            season=season, user_id=black_user_id, defaults={"rating": cls.BASE_RATING}
        )

        white_result, black_result, white_score, black_score = cls._result_tuple(game_result)
        white_old = white_stat.rating
        black_old = black_stat.rating

        white_stat.rating = RatingService.calculate_new_rating(white_old, black_old, white_score)
        black_stat.rating = RatingService.calculate_new_rating(black_old, white_old, black_score)

        white_stat.games_played += 1
        black_stat.games_played += 1
        if white_result == "win":
            white_stat.wins += 1
            black_stat.losses += 1
        elif black_result == "win":
            black_stat.wins += 1
            white_stat.losses += 1
        else:
            white_stat.draws += 1
            black_stat.draws += 1

        white_stat.peak_rating = max(white_stat.peak_rating, white_stat.rating)
        black_stat.peak_rating = max(black_stat.peak_rating, black_stat.rating)
        white_stat.save(
            update_fields=["rating", "games_played", "wins", "losses", "draws", "peak_rating"]
        )
        black_stat.save(
            update_fields=["rating", "games_played", "wins", "losses", "draws", "peak_rating"]
        )
        cls.invalidate_leaderboard_cache()

    @classmethod
    def _leaderboard_queryset(cls, season: Season):
        return (
            SeasonStat.objects.select_related("user", "user__stats")
            .filter(season=season, games_played__gte=cls.MIN_GAMES_FOR_RANK, user__is_guest=False)
            .order_by("-rating", "-wins", "-peak_rating", "id")
        )

    @classmethod
    def _cache_ttl(cls, *, page: int, page_size: int, no_count: bool) -> int:
        # 첫 페이지는 갱신을 빠르게, 나머지 페이지는 캐시를 길게 유지
        if no_count:
            return 20 if page == 1 else 90
        return 15 if page == 1 and page_size <= 20 else 60

    @classmethod
    def get_current_leaderboard(
        cls,
        *,
        page: int,
        page_size: int,
        no_count: bool = False,
    ) -> tuple[Season, SeasonPage]:
        season = cls.get_or_create_current_season()
        if page_size <= 0:
            page_size = 20
        page_size = min(page_size, cls.MAX_PAGE_SIZE)
        if page <= 0:
            page = 1

        version = cls.get_cache_version()
        cache_key = (
            f"season_lb_v{version}_s{season.id}_p{page}_n{page_size}_nc{1 if no_count else 0}"
        )
        cached = cache.get(cache_key)
        if cached is not None:
            return season, cached

        queryset = cls._leaderboard_queryset(season)
        offset = (page - 1) * page_size
        has_next = False
        total = None
        total_pages = None

        if no_count:
            rows = list(queryset[offset : offset + page_size + 1])
            if len(rows) > page_size:
                has_next = True
                rows = rows[:page_size]
        else:
            total = queryset.count()
            total_pages = (total + page_size - 1) // page_size if total else 1
            rows = list(queryset[offset : offset + page_size])
            has_next = page < (total_pages or 1)

        start_rank = offset + 1
        payload_rows = []
        for idx, row in enumerate(rows):
            payload_rows.append(
                {
                    "rank": start_rank + idx,
                    "user_id": row.user_id,
                    "nickname": row.user.nickname,
                    "avatar_url": row.user.avatar_url,
                    "rank_tier": (
                        row.user.stats.rank_tier if hasattr(row.user, "stats") else "Beginner"
                    ),
                    "rating": row.rating,
                    "peak_rating": row.peak_rating,
                    "games_played": row.games_played,
                    "wins": row.wins,
                    "losses": row.losses,
                    "draws": row.draws,
                    "win_rate": row.win_rate,
                }
            )
        payload = SeasonPage(
            count=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=has_next,
            results=payload_rows,
        )
        cache.set(
            cache_key, payload, cls._cache_ttl(page=page, page_size=page_size, no_count=no_count)
        )
        return season, payload

    @classmethod
    def get_current_my_rank(cls, user_id: int) -> tuple[Season, dict | None]:
        season = cls.get_or_create_current_season()
        my = (
            SeasonStat.objects.select_related("user")
            .filter(season=season, user_id=user_id, games_played__gte=cls.MIN_GAMES_FOR_RANK)
            .first()
        )
        if my is None:
            return season, None

        higher_count = (
            SeasonStat.objects.filter(
                season=season,
                games_played__gte=cls.MIN_GAMES_FOR_RANK,
                user__is_guest=False,
            )
            .filter(
                Q(rating__gt=my.rating)
                | Q(rating=my.rating, wins__gt=my.wins)
                | Q(rating=my.rating, wins=my.wins, peak_rating__gt=my.peak_rating)
                | Q(rating=my.rating, wins=my.wins, peak_rating=my.peak_rating, id__lt=my.id)
            )
            .count()
        )
        rank = higher_count + 1
        return season, {
            "rank": rank,
            "rating": my.rating,
            "peak_rating": my.peak_rating,
            "games_played": my.games_played,
            "wins": my.wins,
            "losses": my.losses,
            "draws": my.draws,
            "win_rate": my.win_rate,
            "season_stat_id": my.id,
        }

    @classmethod
    @transaction.atomic
    def finalize_season(cls, season: Season) -> int:
        season = Season.objects.select_for_update().get(pk=season.pk)
        if season.is_finalized:
            return 0

        stats = list(cls._leaderboard_queryset(season))
        for rank, stat in enumerate(stats, start=1):
            stat.final_rank = rank
        if stats:
            SeasonStat.objects.bulk_update(stats, ["final_rank"])

        rewards = list(season.rewards.all())
        claim_rows: list[UserSeasonReward] = []
        notification_rows = []
        for stat in stats:
            matching = [
                reward
                for reward in rewards
                if reward.rank_min <= (stat.final_rank or 0) <= reward.rank_max
            ]
            for reward in matching:
                claim_rows.append(
                    UserSeasonReward(user_id=stat.user_id, season=season, reward=reward)
                )
            notification_rows.append(
                {
                    "user": stat.user,
                    "type": "season_end",
                    "title": f"{season.name} 종료",
                    "message": f"최종 순위 {stat.final_rank}위가 확정되었습니다.",
                    "payload": {"season_id": season.id, "rank": stat.final_rank},
                }
            )
        if claim_rows:
            UserSeasonReward.objects.bulk_create(claim_rows, ignore_conflicts=True)
        if notification_rows:
            NotificationService.bulk_create_notifications(notification_rows, push=True)

        season.is_active = False
        season.is_finalized = True
        season.save(update_fields=["is_active", "is_finalized"])
        cls.invalidate_leaderboard_cache()
        return len(stats)

    @classmethod
    @transaction.atomic
    def check_transition(cls, today: date | None = None) -> dict:
        today = today or timezone.localdate()
        ended = (
            Season.objects.select_for_update()
            .filter(is_active=True, is_finalized=False, end_date__lt=today)
            .order_by("start_date")
        )
        finalized_count = 0
        for season in ended:
            finalized_count += cls.finalize_season(season)

        current = cls.get_or_create_current_season(today=today)
        return {
            "date": str(today),
            "active_season_id": current.id,
            "finalized_users": finalized_count,
        }

    @classmethod
    def list_history(cls, *, limit: int = 12):
        limit = max(1, min(limit, 24))
        return list(Season.objects.filter(is_finalized=True).order_by("-start_date")[:limit])

    @classmethod
    @transaction.atomic
    def claim_rewards(cls, *, user_id: int, season_id: int) -> dict:
        season = Season.objects.filter(pk=season_id).first()
        if season is None:
            raise ValidationError("요청한 시즌을 찾을 수 없습니다.")
        if not season.is_finalized:
            raise ValidationError("시즌 종료 후에만 보상을 수령할 수 있습니다.")

        claims = list(
            UserSeasonReward.objects.select_for_update()
            .select_related("reward")
            .filter(user_id=user_id, season_id=season_id, claimed_at__isnull=True)
        )
        if not claims:
            raise ValidationError("수령 가능한 보상이 없습니다.")

        now = timezone.now()
        for row in claims:
            row.claimed_at = now
        UserSeasonReward.objects.bulk_update(claims, ["claimed_at"])

        points_to_add = 0
        reward_lines: list[str] = []
        for row in claims:
            reward = row.reward
            if reward.reward_type == SeasonReward.TYPE_POINTS:
                try:
                    points_to_add += int(reward.reward_value)
                except (TypeError, ValueError):
                    continue
            else:
                reward_lines.append(f"{reward.get_reward_type_display()}: {reward.reward_value}")

        if points_to_add > 0:
            UserStats.objects.filter(user_id=user_id).update(
                style_points=F("style_points") + points_to_add
            )
            reward_lines.append(f"포인트: +{points_to_add}")

        user_stats = UserStats.objects.select_related("user").filter(user_id=user_id).first()
        if user_stats:
            NotificationService.create_notification(
                user=user_stats.user,
                type="season_reward",
                title="시즌 보상 수령 완료",
                message=", ".join(reward_lines) if reward_lines else "보상을 수령했습니다.",
                payload={"season_id": season_id, "claimed_count": len(claims)},
            )
        return {"claimed_count": len(claims), "rewards": reward_lines}
