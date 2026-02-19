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
        """랭킹 보드 QuerySet 반환 (페이지네이션용) - 게스트 제외"""
        return (
            User.objects.filter(is_active=True, is_guest=False)
            .select_related("stats")
            .annotate(rank=RankingService._rank_window())
            .order_by("-stats__rating", "-stats__games_played", "id")
        )

    @staticmethod
    def get_user_with_rank(user_id: int):
        """특정 유저의 랭킹 정보 조회 (COUNT 기반 랭킹 계산) - 게스트 제외"""
        user = (
            User.objects.filter(pk=user_id, is_active=True, is_guest=False)
            .select_related("stats")
            .first()
        )
        if user is None or not hasattr(user, "stats") or user.stats is None:
            return None

        # 해당 유저보다 높은 순위의 유저 수 + 1 = 해당 유저의 랭킹
        # 정렬 기준: rating DESC, games_played DESC, id ASC
        higher_rank_count = (
            User.objects.filter(
                is_active=True,
                is_guest=False,
                stats__isnull=False,
            )
            .filter(
                # rating이 더 높거나
                Q(stats__rating__gt=user.stats.rating)
                # rating이 같고 games_played가 더 많거나
                | Q(
                    stats__rating=user.stats.rating, stats__games_played__gt=user.stats.games_played
                )
                # 둘 다 같고 id가 더 작은 경우
                | Q(
                    stats__rating=user.stats.rating,
                    stats__games_played=user.stats.games_played,
                    id__lt=user.id,
                )
            )
            .count()
        )

        user.rank = higher_rank_count + 1
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
    def get_users_with_rank(user_ids: list[int]) -> dict[int, int]:
        """여러 유저의 랭킹 일괄 조회 (N+1 방지)

        Returns:
            dict[user_id, rank]: 유저 ID와 랭킹 매핑
        """
        if not user_ids:
            return {}

        # Window 함수로 전체 랭킹 계산 후 필터링 - 게스트 제외
        ranked_users = (
            User.objects.filter(is_active=True, is_guest=False, stats__isnull=False)
            .select_related("stats")
            .annotate(rank=RankingService._rank_window())
            .filter(id__in=user_ids)
            .values("id", "rank")
        )
        return {row["id"]: row["rank"] for row in ranked_users}

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
