"""방 조회 View"""

from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.chess.serializers import PagedRoomSerializer, RoomSerializer
from apps.chess.services import RoomQueryService
from apps.chess.utils import parse_int


class RoomListView(APIView):
    """방 목록 조회 (공개방)"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: PagedRoomSerializer}, tags=["방"])
    def get(self, request):
        limit = parse_int(request.query_params.get("limit"), default=20, min_value=1, max_value=100)
        offset = parse_int(
            request.query_params.get("offset"), default=0, min_value=0, max_value=10_000
        )
        room_type = request.query_params.get("room_type")
        status = request.query_params.get("status")

        total, rooms = RoomQueryService.list_rooms(
            room_type=room_type,
            status=status,
            limit=limit,
            offset=offset,
        )
        data = RoomSerializer(rooms, many=True).data
        return Response({"count": total, "results": data})


class RoomDetailView(APIView):
    """방 상세 조회"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: RoomSerializer}, tags=["방"])
    def get(self, request, room_id: int):
        room = RoomQueryService.get_room(room_id, request.user)
        return Response(RoomSerializer(room).data)
