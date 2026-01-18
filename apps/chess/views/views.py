from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.chess.services import MatchmakingService


class QuickMatchView(APIView):
    """빠른 대전 매칭"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        room, game, status = MatchmakingService.quick_match(request.user)
        data = {
            "status": status,
            "room_id": room.id,
            "game_id": game.id if game else None,
            "room_status": room.status,
        }
        return Response(data)
