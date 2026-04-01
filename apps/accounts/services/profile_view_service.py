"""프로필/대시보드 조회 조립 서비스."""

from __future__ import annotations

from django.core.cache import cache
from django.db.models import Q

from apps.accounts.models import Friend, FriendRequest, SeasonStat, User
from apps.chess.serializers.game_serializers import GameHistorySerializer
from apps.chess.services.game_query_service import GameQueryService

from .achievement_service import AchievementService
from .presence_service import PresenceService
from .season_stat_service import SeasonStatService
from .user_stats_service import UserStatsService


class ProfileViewService:
    """프로필/대시보드 조회 응답 조립을 담당한다."""

    PROFILE_CACHE_TTL_SECONDS = 60 * 5
    USER_ONLY_FIELDS = (
        "id",
        "nickname",
        "email",
        "avatar_url",
        "bio",
        "created_at",
        "updated_at",
        "stats__rating",
        "stats__games_played",
        "stats__games_won",
        "stats__games_lost",
        "stats__games_draw",
        "stats__competitive_games_played",
        "stats__style_points",
        "stats__nickname_color",
        "stats__profile_border",
        "stats__owned_nickname_colors",
        "stats__owned_profile_borders",
        "stats__season_title",
        "stats__profile_card_frame",
        "stats__owned_season_titles",
        "stats__owned_profile_card_frames",
        "stats__earned_achievement_keys",
        "stats__featured_achievement_key",
        "stats__selected_board_skin_id",
        "stats__selected_piece_skin_id",
        "stats__selected_board_skin__css_class",
        "stats__selected_piece_skin__css_class",
    )
    PREVIOUS_SEASON_ONLY_FIELDS = (
        "season_id",
        "season__name",
        "season__start_date",
        "final_rank",
        "games_played",
        "wins",
        "losses",
        "draws",
        "rating",
        "peak_rating",
    )

    @classmethod
    def build_user_profile_payload(cls, *, viewer, user_id: int) -> dict | None:
        user = cls._get_user_with_stats(user_id=user_id)
        if user is None:
            return None

        recent_games = GameQueryService.list_recent_for_user(user, limit=20)
        previous_season = cls._get_previous_season_summary(user_id=user_id)
        vs_summary = None
        friend_status = None

        if viewer.is_authenticated and viewer.pk != user_id:
            vs_summary = GameQueryService.head_to_head_summary(viewer, user)
            friend_status = cls._build_friend_status(viewer_id=viewer.pk, user_id=user_id)

        return {
            "user": cls._build_public_user_payload(user),
            "achievements": AchievementService.get_profile_achievements(user),
            "recent_games": GameHistorySerializer(recent_games, many=True).data,
            "vs_summary": vs_summary,
            "previous_season": previous_season,
            "friend_status": friend_status,
        }

    @classmethod
    def build_dashboard_payload(cls, *, user: User) -> dict:
        user = cls._get_user_with_stats(user_id=user.pk, include_email=True)
        stats = user.stats
        recent_games = GameQueryService.list_recent_for_user(user, limit=10)
        return {
            "user": cls._build_public_user_payload(user),
            "summary": {
                "rating": stats.rating,
                "rank_tier": UserStatsService.get_rank_tier(stats),
                "games_played": stats.games_played,
                "games_won": stats.games_won,
                "games_lost": stats.games_lost,
                "games_draw": stats.games_draw,
                "win_rate": UserStatsService.get_win_rate(stats),
                "style_points": stats.style_points,
            },
            "achievements": AchievementService.get_profile_achievements(user),
            "recent_games": GameHistorySerializer(recent_games, many=True).data,
        }

    @classmethod
    def _get_user_with_stats(cls, *, user_id: int, include_email: bool = False) -> User | None:
        only_fields = (
            cls.USER_ONLY_FIELDS
            if include_email
            else tuple(field for field in cls.USER_ONLY_FIELDS if field != "email")
        )
        return (
            User.objects.select_related(
                "stats",
                "stats__selected_board_skin",
                "stats__selected_piece_skin",
            )
            .only(*only_fields)
            .filter(pk=user_id)
            .first()
        )

    @classmethod
    def _build_public_user_payload(cls, user: User) -> dict:
        cache_key = f"user_profile:{user.id}:public"
        cached = cache.get(cache_key)
        if cached is None:
            stats = user.stats
            cached = {
                "id": user.id,
                "nickname": user.nickname,
                "avatar_url": user.avatar_url,
                "bio": user.bio,
                "created_at": user.created_at,
                "stats": {
                    "rating": stats.rating,
                    "games_played": stats.games_played,
                    "games_won": stats.games_won,
                    "games_lost": stats.games_lost,
                    "games_draw": stats.games_draw,
                    "rank_tier": UserStatsService.get_rank_tier(stats),
                    "win_rate": UserStatsService.get_win_rate(stats),
                    "style_points": stats.style_points,
                    "nickname_color": stats.nickname_color,
                    "profile_border": stats.profile_border,
                    "unlocked_nickname_colors": UserStatsService.get_nickname_color_options(stats),
                    "unlocked_profile_borders": UserStatsService.get_profile_border_options(stats),
                    "season_title": stats.season_title,
                    "profile_card_frame": stats.profile_card_frame,
                    "owned_season_titles": list(stats.owned_season_titles or []),
                    "owned_profile_card_frames": list(stats.owned_profile_card_frames or []),
                    "available_season_titles": UserStatsService.get_available_season_titles(stats),
                    "available_profile_card_frames": UserStatsService.get_available_profile_card_frames(
                        stats
                    ),
                    "earned_achievement_keys": list(stats.earned_achievement_keys or []),
                    "featured_achievement_key": stats.featured_achievement_key,
                    "selected_board_skin_class": UserStatsService.get_selected_board_skin_class(
                        stats
                    ),
                    "selected_piece_skin_class": UserStatsService.get_selected_piece_skin_class(
                        stats
                    ),
                },
                "featured_achievement": AchievementService.get_featured_achievement_for_stats(
                    stats
                ),
            }
            cache.set(cache_key, cached, cls.PROFILE_CACHE_TTL_SECONDS)

        payload = dict(cached)
        presence = PresenceService.get_presence(user.id)
        payload["online"] = presence["online"]
        payload["status"] = presence["status"]
        payload["status_label"] = presence["status_label"]
        return payload

    @staticmethod
    def _build_friend_status(*, viewer_id: int, user_id: int) -> dict:
        request_pairs = set(
            FriendRequest.objects.filter(
                (Q(from_user_id=viewer_id) & Q(to_user_id=user_id))
                | (Q(from_user_id=user_id) & Q(to_user_id=viewer_id))
            ).values_list("from_user_id", "to_user_id")
        )
        return {
            "is_friend": Friend.objects.filter(user_id=viewer_id, friend_id=user_id).exists(),
            "is_request_sent": (viewer_id, user_id) in request_pairs,
            "is_request_received": (user_id, viewer_id) in request_pairs,
        }

    @staticmethod
    def _get_previous_season_summary(*, user_id: int) -> dict | None:
        previous_season = (
            SeasonStat.objects.select_related("season")
            .only(*ProfileViewService.PREVIOUS_SEASON_ONLY_FIELDS)
            .filter(user_id=user_id, season__is_finalized=True)
            .order_by("-season__start_date")
            .first()
        )
        if previous_season is None:
            return None

        return {
            "season_id": previous_season.season_id,
            "season_name": previous_season.season.name,
            "final_rank": previous_season.final_rank,
            "games_played": previous_season.games_played,
            "wins": previous_season.wins,
            "losses": previous_season.losses,
            "draws": previous_season.draws,
            "win_rate": SeasonStatService.get_win_rate(previous_season),
            "rating": previous_season.rating,
            "peak_rating": previous_season.peak_rating,
        }
