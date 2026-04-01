from __future__ import annotations

from django.shortcuts import get_object_or_404

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import Season, UserSeasonReward
from apps.accounts.serializers.season_serializers import (
    SeasonRewardSerializer,
    SeasonSerializer,
)
from apps.accounts.services import SeasonService


class SeasonLeaderboardQuerySerializer(serializers.Serializer):
    page = serializers.IntegerField(required=False, default=1, min_value=1)
    page_size = serializers.IntegerField(required=False, default=20, min_value=1, max_value=100)
    no_count = serializers.BooleanField(required=False, default=False)


class SeasonHistoryQuerySerializer(serializers.Serializer):
    limit = serializers.IntegerField(required=False, default=12, min_value=1, max_value=24)


class CurrentSeasonView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(responses={200: SeasonSerializer}, tags=["시즌"])
    def get(self, request):
        season = SeasonService.get_or_create_current_season()
        return Response(SeasonSerializer(season).data)


class CurrentSeasonLeaderboardView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        parameters=[
            OpenApiParameter("page", int, OpenApiParameter.QUERY, required=False),
            OpenApiParameter("page_size", int, OpenApiParameter.QUERY, required=False),
            OpenApiParameter("no_count", bool, OpenApiParameter.QUERY, required=False),
        ],
        tags=["시즌"],
    )
    def get(self, request):
        query = SeasonLeaderboardQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        page = query.validated_data["page"]
        page_size = query.validated_data["page_size"]
        no_count = query.validated_data["no_count"]
        season, data = SeasonService.get_current_leaderboard(
            page=page, page_size=page_size, no_count=no_count
        )
        return Response(
            {
                "season": SeasonSerializer(season).data,
                "count": data.count,
                "total_pages": data.total_pages,
                "current_page": data.page,
                "has_next": data.has_next,
                "results": data.results,
                "min_games_for_rank": SeasonService.MIN_GAMES_FOR_RANK,
            }
        )


class CurrentSeasonMeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(tags=["시즌"])
    def get(self, request):
        season, my_rank = SeasonService.get_current_my_rank(request.user.id)
        return Response(
            {
                "season": SeasonSerializer(season).data,
                "my_rank": my_rank,
                "min_games_for_rank": SeasonService.MIN_GAMES_FOR_RANK,
            }
        )


class SeasonHistoryView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(tags=["시즌"])
    def get(self, request):
        query = SeasonHistoryQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        items = SeasonService.get_history_with_rewards(
            limit=query.validated_data["limit"],
            user_id=request.user.id if request.user.is_authenticated else None,
        )
        return Response({"count": len(items), "results": items})


class SeasonDetailView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(tags=["시즌"])
    def get(self, request, season_id: int):
        season = get_object_or_404(Season, pk=season_id)
        return Response(SeasonSerializer(season).data)


class SeasonRewardListView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(tags=["시즌"])
    def get(self, request, season_id: int):
        season = get_object_or_404(Season, pk=season_id)
        rewards = season.rewards.all()
        claimed_reward_ids = set()
        if request.user.is_authenticated:
            claimed_reward_ids = set(
                UserSeasonReward.objects.filter(
                    user=request.user,
                    season=season,
                    claimed_at__isnull=False,
                ).values_list("reward_id", flat=True)
            )
        payload = []
        for reward in rewards:
            row = SeasonRewardSerializer(reward).data
            row["reward_value"] = SeasonService.get_reward_display_value(
                season=season, reward=reward
            )
            row["reward_key"] = SeasonService.get_reward_raw_value(season=season, reward=reward)
            row["claimed"] = reward.id in claimed_reward_ids
            payload.append(row)
        return Response({"season": SeasonSerializer(season).data, "results": payload})


class SeasonRewardClaimView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(tags=["시즌"])
    def post(self, request, season_id: int):
        result = SeasonService.claim_rewards(user_id=request.user.id, season_id=season_id)
        return Response(result)
