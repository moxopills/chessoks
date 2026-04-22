"""게임 조회 View"""

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsAuthenticatedOrGuest
from apps.chess.serializers import (
    GameDetailSerializer,
    GameSummarySerializer,
    MoveSerializer,
    PagedMoveSerializer,
)
from apps.chess.services import GameQueryService, GameService
from apps.core.request import parse_pagination_query


class GameDetailView(APIView):
    """게임 상태 조회 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: GameDetailSerializer}, tags=["게임"])
    def get(self, request, game_id: int):
        game = GameQueryService.get_game_for_user(game_id, request.user)
        return Response(GameDetailSerializer(game).data)


class GameMoveListView(APIView):
    """게임 착수 목록 조회 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: PagedMoveSerializer}, tags=["게임"])
    def get(self, request, game_id: int):
        limit, offset, _ = parse_pagination_query(
            request.query_params,
            default_limit=50,
            max_limit=200,
        )
        total, moves = GameQueryService.list_moves(game_id, request.user, limit, offset)
        return Response({"count": total, "results": MoveSerializer(moves, many=True).data})


class GameLegalMoveView(APIView):
    """게임 합법 수 조회 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(
        responses={200: None},
        tags=["게임"],
        description="현재 턴 기준 합법 수 UCI 목록 반환",
    )
    def get(self, request, game_id: int):
        from_square = request.query_params.get("from")
        moves = GameQueryService.list_legal_moves(game_id, request.user, from_square)
        return Response({"moves": moves})


class GameCapturedView(APIView):
    """잡힌 기물 요약 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: None}, tags=["게임"])
    def get(self, request, game_id: int):
        captured = GameQueryService.captured_summary(game_id, request.user)
        return Response(captured)


class GameSummaryView(APIView):
    """게임 종료 요약 조회 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: GameSummarySerializer}, tags=["게임"])
    def get(self, request, game_id: int):
        summary = GameQueryService.get_summary(game_id, request.user)
        return Response(summary)


class GameRematchView(APIView):
    """리매치 요청/수락 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: None}, tags=["게임"])
    def post(self, request, game_id: int):
        rematch_game, status, _ = GameService.request_rematch(game_id, request.user)
        payload = {"status": status}
        if rematch_game:
            payload["rematch_game_id"] = rematch_game.id
            payload["room_id"] = rematch_game.room_id
            channel_layer = get_channel_layer()
            if channel_layer is not None:
                async_to_sync(channel_layer.group_send)(
                    f"chess_room_{rematch_game.room_id}",
                    {
                        "type": "broadcast",
                        "payload": {
                            "type": "rematch_created",
                            "game_id": rematch_game.id,
                            "room_id": rematch_game.room_id,
                        },
                    },
                )
        return Response(payload)
