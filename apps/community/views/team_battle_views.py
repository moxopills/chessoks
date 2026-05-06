from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.community.serializers import (
    TeamBattleCreateSerializer,
    TeamBattleJoinSerializer,
    TeamBattleMatchDetailSerializer,
    TeamBattleRoundResultSerializer,
)
from apps.community.services import TeamBattleService
from apps.core.request import parse_bool_query


class TeamBattleListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        matches = TeamBattleService.list_matches()
        no_count = parse_bool_query(request.query_params.get("no_count"))
        results = TeamBattleMatchDetailSerializer(matches, many=True).data
        return Response(
            {
                "count": len(results) if no_count else matches.count(),
                "results": results,
            }
        )

    def post(self, request):
        serializer = TeamBattleCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if data["battle_type"] == "party":
            match = TeamBattleService.create_party_match(
                request.user, party_id=data.get("party_id")
            )
        else:
            match = TeamBattleService.create_guild_match(
                request.user, guild_id=data.get("guild_id")
            )
        return Response(TeamBattleMatchDetailSerializer(match).data, status=201)


class TeamBattleJoinView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, match_id: int):
        serializer = TeamBattleJoinSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if data.get("party_id"):
            match = TeamBattleService.join_party_match(
                request.user, match_id=match_id, party_id=data["party_id"]
            )
        else:
            match = TeamBattleService.join_guild_match(
                request.user, match_id=match_id, guild_id=data["guild_id"]
            )
        return Response(TeamBattleMatchDetailSerializer(match).data)


class TeamBattleStartView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, match_id: int):
        match = TeamBattleService.start_match(request.user, match_id=match_id)
        return Response(TeamBattleMatchDetailSerializer(match).data)


class TeamBattleRoundResultView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, match_id: int, round_id: int):
        serializer = TeamBattleRoundResultSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        match = TeamBattleService.report_round_result(
            request.user,
            match_id=match_id,
            round_id=round_id,
            result=serializer.validated_data["result"],
        )
        return Response(TeamBattleMatchDetailSerializer(match).data)
