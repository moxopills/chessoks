"""랭킹/온라인 상태/프로필 조회 관련 View."""

from django.core.cache import cache

from drf_spectacular.utils import extend_schema
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from apps.accounts.models import User
from apps.accounts.serializers import (
    DashboardSerializer,
    LeaderboardEntrySerializer,
    LeaderboardResponseSerializer,
    OnlineStatusListSerializer,
    OnlineStatusSerializer,
    OnlineUsersListSerializer,
    OpponentProfileSerializer,
    PresenceUpdateSerializer,
    PublicUserSerializer,
)
from apps.accounts.services import PresenceService, ProfileViewService, RankingService
from apps.core.throttling import PresenceActionThrottle


class LeaderboardView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]
    CACHE_TTL = 60

    @extend_schema(parameters=[], responses={200: LeaderboardResponseSerializer}, tags=["랭킹"])
    def get(self, request):
        from apps.accounts.pagination import LeaderboardPagination

        version = RankingService.get_cache_version()
        page_num = request.query_params.get("page", "1")
        page_size = request.query_params.get("page_size", "20")
        cache_key = f"leaderboard_v{version}_p{page_num}_s{page_size}"
        cached_data = cache.get(cache_key)
        if cached_data is None:
            queryset = RankingService.get_leaderboard_queryset()
            paginator = LeaderboardPagination()
            page = paginator.paginate_queryset(queryset, request)
            cached_data = {
                "entries": LeaderboardEntrySerializer(page, many=True).data,
                "count": paginator.page.paginator.count,
                "total_pages": paginator.page.paginator.num_pages,
                "current_page": paginator.page.number,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link(),
            }
            cache.set(cache_key, cached_data, self.CACHE_TTL)

        my_rank = None
        if request.user.is_authenticated:
            my_rank_cache_key = f"my_rank_v{version}_{request.user.pk}"
            my_rank = cache.get(my_rank_cache_key)
            if my_rank is None:
                my_rank = RankingService.get_my_rank_data(request.user.pk)
                cache.set(my_rank_cache_key, my_rank, self.CACHE_TTL)

        return Response(
            {
                "count": cached_data["count"],
                "total_pages": cached_data["total_pages"],
                "current_page": cached_data["current_page"],
                "next": cached_data["next"],
                "previous": cached_data["previous"],
                "results": cached_data["entries"],
                "my_rank": my_rank,
            }
        )


class MyRankView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: LeaderboardEntrySerializer}, tags=["랭킹"])
    def get(self, request):
        user = RankingService.get_user_with_rank(request.user.pk)
        if user is None:
            return Response({"message": "유저 정보를 찾을 수 없습니다."}, status=400)
        return Response(LeaderboardEntrySerializer(user).data)


class OnlineStatusView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: OnlineStatusListSerializer}, tags=["유저"])
    def get(self, request):
        ids = _parse_id_list(request.query_params.get("ids", ""))
        statuses = PresenceService.bulk_presence(ids) if ids else {}
        data = [
            OnlineStatusSerializer({"id": user_id, **statuses.get(user_id, {})}).data
            for user_id in ids
        ]
        return Response({"results": data})


class OnlineUsersView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: OnlineUsersListSerializer}, tags=["유저"])
    def get(self, request):
        users = PresenceService.list_online_users()
        return Response({"count": len(users), "results": users})


class PresenceUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [PresenceActionThrottle]

    @extend_schema(
        request=PresenceUpdateSerializer, responses={200: PresenceUpdateSerializer}, tags=["유저"]
    )
    def post(self, request):
        serializer = PresenceUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        status = serializer.validated_data["status"]
        room_id = serializer.validated_data.get("room_id")
        game_id = serializer.validated_data.get("game_id")
        scope_id = serializer.validated_data.get("scope_id") or ""
        active = serializer.validated_data.get("active", True)
        scope = (
            f"{status}:{scope_id}"
            if scope_id
            else PresenceService.build_scope(status, room_id=room_id, game_id=game_id)
        )

        if active:
            PresenceService.set_presence(
                request.user.id, status, scope=scope, room_id=room_id, game_id=game_id
            )
        else:
            PresenceService.clear_presence(
                request.user.id, scope=scope, status=status, room_id=room_id, game_id=game_id
            )

        payload = PresenceService.get_presence(request.user.id)
        return Response(
            {
                "status": payload["status"],
                "status_label": payload["status_label"],
                "online": payload["online"],
                "room_id": payload.get("room_id"),
                "game_id": payload.get("game_id"),
            }
        )


class UserProfileView(APIView):
    permission_classes = [AllowAny]
    CACHE_TTL = 300

    @extend_schema(responses={200: OpponentProfileSerializer}, tags=["유저"])
    def get(self, request, user_id: int):
        payload = ProfileViewService.build_user_profile_payload(
            viewer=request.user, user_id=user_id
        )
        if payload is None:
            return Response({"message": "유저 정보를 찾을 수 없습니다."}, status=404)
        return Response(payload)


class UserDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: DashboardSerializer}, tags=["통계"])
    def get(self, request):
        return Response(ProfileViewService.build_dashboard_payload(user=request.user))


class UserSearchView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: PublicUserSerializer(many=True)}, tags=["유저"])
    def get(self, request):
        query = request.query_params.get("q", "").strip()
        if not query:
            return Response({"count": 0, "results": []})

        queryset = (
            User.objects.select_related("stats")
            .filter(nickname__icontains=query)
            .order_by("nickname")[:20]
        )
        return Response(
            {
                "count": len(queryset),
                "results": PublicUserSerializer(queryset, many=True).data,
            }
        )


def _parse_id_list(value: str) -> list[int]:
    if not value:
        return []
    ids = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdigit():
            ids.append(int(part))
    return ids
