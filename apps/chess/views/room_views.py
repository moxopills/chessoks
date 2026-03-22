"""방 조회 View"""

from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsAuthenticatedOrGuest
from apps.chess.serializers import (
    PagedRoomSerializer,
    RoomCreateRequestSerializer,
    RoomJoinRequestSerializer,
    RoomReadyRequestSerializer,
    RoomReadyResponseSerializer,
    RoomSerializer,
    RoomStartConfirmResponseSerializer,
)
from apps.chess.services import RoomFlowService, RoomQueryService
from apps.core.request import parse_pagination_query


class RoomListView(APIView):
    """방 목록 조회/생성 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: PagedRoomSerializer}, tags=["방"])
    def get(self, request):
        limit, offset, no_count = parse_pagination_query(
            request.query_params,
            default_limit=20,
            max_limit=100,
        )
        room_type = request.query_params.get("room_type")
        status = request.query_params.get("status")

        total, rooms = RoomQueryService.list_rooms(
            user=request.user,
            room_type=room_type,
            status=status,
            limit=limit,
            offset=offset,
            no_count=no_count,
        )
        data = RoomSerializer(rooms, many=True).data
        return Response({"count": total, "results": data})

    @extend_schema(
        request=RoomCreateRequestSerializer,
        responses={201: RoomSerializer},
        tags=["방"],
    )
    def post(self, request):
        """방 생성"""
        serializer = RoomCreateRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        room = RoomQueryService.create_room(
            request.user,
            room_type=data.get("room_type", "custom"),
            title=data.get("title", ""),
            time_limit=data.get("time_limit", 15),
            increment_seconds=data.get("increment_seconds", 10),
            password=data.get("password", ""),
            allow_spectators=data.get("allow_spectators", True),
        )
        return Response(RoomSerializer(room).data, status=201)


class RoomDetailView(APIView):
    """방 상세 조회 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: RoomSerializer}, tags=["방"])
    def get(self, request, room_id: int):
        room = RoomQueryService.get_room(room_id, request.user)
        return Response(RoomSerializer(room).data)


class RoomWaitingView(APIView):
    """내 대기 방 조회 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: RoomSerializer}, tags=["방"])
    def get(self, request):
        room = RoomQueryService.get_waiting_room(request.user)
        if not room:
            return Response({"room": None})
        return Response({"room": RoomSerializer(room).data})


class RoomActiveView(APIView):
    """내 진행 중 방 조회 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: RoomSerializer}, tags=["방"])
    def get(self, request):
        room = RoomQueryService.get_active_room(request.user)
        if not room:
            return Response({"room": None})
        return Response({"room": RoomSerializer(room).data})


class RoomReadyView(APIView):
    """방 준비 상태 변경 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(
        request=RoomReadyRequestSerializer,
        responses={200: RoomReadyResponseSerializer},
        tags=["방"],
    )
    def post(self, request, room_id: int):
        serializer = RoomReadyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        room = RoomFlowService.set_ready(room_id, request.user, serializer.validated_data["ready"])
        return Response(
            {
                "room_id": room.id,
                "status": room.status,
                "host_ready": room.host_ready,
                "guest_ready": room.guest_ready,
                "host_start_confirmed": room.host_start_confirmed,
                "guest_start_confirmed": room.guest_start_confirmed,
            }
        )


class RoomStartConfirmView(APIView):
    """게임 시작 승인 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: RoomStartConfirmResponseSerializer}, tags=["방"])
    def post(self, request, room_id: int):
        room, game = RoomFlowService.confirm_start(room_id, request.user)
        return Response(
            {
                "room_id": room.id,
                "status": room.status,
                "game_id": game.id if game else None,
                "host_start_confirmed": room.host_start_confirmed,
                "guest_start_confirmed": room.guest_start_confirmed,
            }
        )


class RoomJoinView(APIView):
    """방 입장 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(
        request=RoomJoinRequestSerializer,
        responses={200: RoomSerializer},
        tags=["방"],
    )
    def post(self, request, room_id: int):
        serializer = RoomJoinRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        room = RoomFlowService.join_room(
            room_id, request.user, serializer.validated_data.get("password")
        )
        return Response(RoomSerializer(room).data)


class RoomLeaveView(APIView):
    """방 나가기 (게스트 가능)"""

    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: {"type": "object"}}, tags=["방"])
    def post(self, request, room_id: int):
        deleted, room = RoomFlowService.leave_room(room_id, request.user)
        if deleted:
            return Response({"deleted": True, "room_id": room_id})
        return Response({"deleted": False, "room": RoomSerializer(room).data})
