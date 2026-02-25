"""관전자 View"""

from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.chess.serializers import BaseUserSerializer, SpectatorListSerializer
from apps.chess.services import SpectatorService


class SpectatorListView(APIView):
    """관전자 목록"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: SpectatorListSerializer}, tags=["관전"])
    def get(self, request, room_id: int):
        room, spectators = SpectatorService.list_spectators(room_id, request.user)
        return Response(
            {
                "room_id": room.id,
                "spectators": BaseUserSerializer(spectators, many=True).data,
            }
        )


class SpectatorJoinView(APIView):
    """관전 참여"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: SpectatorListSerializer}, tags=["관전"])
    def post(self, request, room_id: int):
        room = SpectatorService.add_spectator(room_id, request.user)
        return Response(
            {
                "room_id": room.id,
                "spectators": BaseUserSerializer(room.spectators.all(), many=True).data,
            }
        )


class SpectatorLeaveView(APIView):
    """관전 나가기"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: SpectatorListSerializer}, tags=["관전"])
    def post(self, request, room_id: int):
        room = SpectatorService.remove_spectator(room_id, request.user)
        return Response(
            {
                "room_id": room.id,
                "spectators": BaseUserSerializer(room.spectators.all(), many=True).data,
            }
        )
