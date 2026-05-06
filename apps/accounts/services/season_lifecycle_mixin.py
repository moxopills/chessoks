from __future__ import annotations

import calendar
from datetime import date

from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import Season


class SeasonLifecycleMixin:
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
    def _finalize_ended_seasons_locked(cls, today: date) -> int:
        ended = (
            Season.objects.select_for_update()
            .filter(is_active=True, is_finalized=False, end_date__lt=today)
            .order_by("start_date")
        )
        finalized_count = 0
        for season in ended:
            finalized_count += cls.finalize_season(season)
        return finalized_count

    @classmethod
    def _get_or_create_current_season_locked(cls, today: date) -> Season:
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
    @transaction.atomic
    def get_or_create_current_season(cls, today: date | None = None) -> Season:
        today = today or timezone.localdate()
        cls._finalize_ended_seasons_locked(today)
        return cls._get_or_create_current_season_locked(today)
