from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.serializers import (
    FriendListSerializer,
    FriendRequestCreateSerializer,
    FriendRequestListSerializer,
    FriendRequestSerializer,
    FriendSerializer,
)
from apps.accounts.services import FriendService


class FriendListView(APIView):
    """친구 목록"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: FriendListSerializer}, tags=["친구"])
    def get(self, request):
        friends = FriendService.list_friends(request.user)
        return Response({"count": len(friends), "results": FriendSerializer(friends, many=True).data})


class FriendRequestListCreateView(APIView):
    """친구 요청 목록/생성"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: FriendRequestListSerializer}, tags=["친구"])
    def get(self, request):
        direction = request.query_params.get("type", "incoming")
        if direction not in ("incoming", "outgoing"):
            direction = "incoming"
        requests = FriendService.list_requests(request.user, direction=direction)
        return Response(
            {"count": len(requests), "results": FriendRequestSerializer(requests, many=True).data}
        )

    @extend_schema(request=FriendRequestCreateSerializer, responses={201: dict}, tags=["친구"])
    def post(self, request):
        serializer = FriendRequestCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = FriendService.send_request(request.user, serializer.validated_data["user_id"])
        status_code = 201 if result["status"] == "requested" else 200
        return Response(result, status=status_code)


class FriendRequestAcceptView(APIView):
    """친구 요청 수락"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: dict}, tags=["친구"])
    def post(self, request, request_id: int):
        FriendService.accept_request(request.user, request_id)
        return Response({"status": "accepted"})


class FriendRequestRejectView(APIView):
    """친구 요청 거절"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: dict}, tags=["친구"])
    def post(self, request, request_id: int):
        FriendService.reject_request(request.user, request_id)
        return Response({"status": "rejected"})
