"""전적 조회 View"""

from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsAuthenticatedOrGuest
from apps.chess.serializers import GameHistorySerializer, PagedGameHistorySerializer
from apps.chess.services import GameQueryService
from apps.core.request import parse_pagination_query


class GameHistoryView(APIView):
    """전적 검색/목록"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: PagedGameHistorySerializer}, tags=["전적"])
    def get(self, request):
        limit, offset, no_count = parse_pagination_query(
            request.query_params,
            default_limit=20,
            max_limit=100,
        )
        opponent = request.query_params.get("opponent")
        start_date = request.query_params.get("start_date")
        end_date = request.query_params.get("end_date")
        result = request.query_params.get("result")
        room_type = request.query_params.get("room_type")

        total, games = GameQueryService.list_history(
            request.user,
            opponent=opponent,
            start_date=start_date,
            end_date=end_date,
            result=result,
            room_type=room_type,
            limit=limit,
            offset=offset,
            no_count=no_count,
        )
        data = GameHistorySerializer(games, many=True).data
        return Response({"count": total, "results": data})
