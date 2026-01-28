"""랭킹 서비스"""

from django.core.cache import cache
from django.db.models import F, Q
from django.db.models.expressions import Window
from django.db.models.functions import Rank

from apps.accounts.models import User

LEADERBOARD_VERSION_KEY = "leaderboard_version"


class RankingService:
    """레이팅 기반 랭킹 서비스"""

    @staticmethod
    def get_leaderboard_queryset():
        """랭킹 보드 QuerySet 반환 (페이지네이션용)"""
        return (
            User.objects.filter(is_active=True)
            .select_related("stats")
            .annotate(rank=RankingService._rank_window())
            .order_by("-stats__rating", "-stats__games_played", "id")
        )

    @staticmethod
    def get_user_with_rank(user_id: int):
        """특정 유저의 랭킹 정보 조회"""
        user = User.objects.filter(pk=user_id, is_active=True).select_related("stats").first()
        if user is None or not hasattr(user, "stats") or user.stats is None:
            return None

        user.rank = RankingService._calculate_rank(user)
        return user

    @staticmethod
    def get_my_rank_data(user_id: int) -> dict | None:
        """내 랭킹 데이터 반환 (리더보드 응답에 포함용)"""
        user = RankingService.get_user_with_rank(user_id)
        if user is None:
            return None
        return {
            "id": user.id,
            "nickname": user.nickname,
            "avatar_url": user.avatar_url,
            "rating": user.stats.rating,
            "games_played": user.stats.games_played,
            "games_won": user.stats.games_won,
            "games_draw": user.stats.games_draw,
            "games_lost": user.stats.games_lost,
            "rank_tier": user.stats.rank_tier,
            "rank": user.rank,
        }

    @staticmethod
    def _calculate_rank(user: User) -> int:
        """유저의 랭킹 계산 (자신보다 높은 유저 수 + 1)"""
        rating = user.stats.rating
        games_played = user.stats.games_played
        higher_count = (
            User.objects.filter(is_active=True)
            .filter(
                Q(stats__rating__gt=rating)
                | Q(stats__rating=rating, stats__games_played__gt=games_played)
                | Q(stats__rating=rating, stats__games_played=games_played, id__lt=user.id)
            )
            .count()
        )
        return higher_count + 1

    @staticmethod
    def _rank_window():
        """랭킹 Window 함수"""
        return Window(
            expression=Rank(),
            order_by=[
                F("stats__rating").desc(),
                F("stats__games_played").desc(),
                F("id").asc(),
            ],
        )

    @staticmethod
    def get_cache_version() -> int:
        """리더보드 캐시 버전 조회"""
        version = cache.get(LEADERBOARD_VERSION_KEY)
        return version if version is not None else 0

    @staticmethod
    def invalidate_leaderboard_cache():
        """리더보드 캐시 무효화 (레이팅 변경 시 버전 증가)"""
        try:
            cache.incr(LEADERBOARD_VERSION_KEY)
        except ValueError:
            cache.set(LEADERBOARD_VERSION_KEY, 1)
