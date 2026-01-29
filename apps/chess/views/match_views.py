"""매칭 관련 View"""

from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.chess.models import Game
from apps.chess.serializers import CancelMatchResponseSerializer, QuickMatchResponseSerializer
from apps.chess.services import MatchmakingService
from apps.chess.utils import assign_colors


class QuickMatchView(APIView):
    """빠른 대전 매칭"""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=None,
        responses={200: QuickMatchResponseSerializer},
        tags=["게임매칭"],
    )
    def post(self, request):
        room, game, status = MatchmakingService.quick_match(request.user)
        if status == "matched" and game is None:
            game = room.games.filter(result="playing").first()
            if game is None:
                white_player, black_player = assign_colors(room.host, room.guest)
                game = Game.objects.create(
                    room=room, white_player=white_player, black_player=black_player
                )
        data = {
            "status": status,
            "room_id": room.id,
            "game_id": game.id if game else None,
        }
        return Response(data)


class CancelMatchView(APIView):
    """빠른 대전 매칭 취소"""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=None,
        responses={200: CancelMatchResponseSerializer},
        tags=["게임매칭"],
    )
    def post(self, request):
        cancelled = MatchmakingService.cancel_match(request.user)
        return Response({"cancelled": cancelled})
