"""게임 조회 View"""

from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.chess.serializers import GameDetailSerializer, MoveSerializer, PagedMoveSerializer
from apps.chess.services import GameQueryService
from apps.chess.utils import parse_int


class GameDetailView(APIView):
    """게임 상태 조회"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: GameDetailSerializer}, tags=["게임"])
    def get(self, request, game_id: int):
        game = GameQueryService.get_game_for_user(game_id, request.user)
        return Response(GameDetailSerializer(game).data)


class GameMoveListView(APIView):
    """게임 착수 목록 조회"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: PagedMoveSerializer}, tags=["게임"])
    def get(self, request, game_id: int):
        limit = parse_int(request.query_params.get("limit"), default=50, min_value=1, max_value=200)
        offset = parse_int(
            request.query_params.get("offset"), default=0, min_value=0, max_value=10_000
        )
        total, moves = GameQueryService.list_moves(game_id, request.user, limit, offset)
        return Response({"count": total, "results": MoveSerializer(moves, many=True).data})
