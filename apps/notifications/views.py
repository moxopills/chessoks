from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.chess.utils import parse_int
from apps.notifications.serializers import (
    NotificationListSerializer,
    NotificationReadSerializer,
    NotificationSerializer,
    NotificationUnreadSerializer,
)
from apps.notifications.services import NotificationService


class NotificationListView(APIView):
    """알림 목록"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: NotificationListSerializer}, tags=["알림"])
    def get(self, request):
        limit = parse_int(request.query_params.get("limit"), default=20, min_value=1, max_value=100)
        offset = parse_int(
            request.query_params.get("offset"), default=0, min_value=0, max_value=10_000
        )
        no_count = request.query_params.get("no_count") in ("1", "true", "True")
        total, items = NotificationService.list_notifications(
            request.user, limit=limit, offset=offset, no_count=no_count
        )
        return Response({"count": total, "results": NotificationSerializer(items, many=True).data})


class NotificationReadView(APIView):
    """알림 읽음 처리"""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=NotificationReadSerializer,
        responses={200: {"type": "object", "properties": {"updated": {"type": "integer"}}}},
        tags=["알림"],
    )
    def post(self, request):
        serializer = NotificationReadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        updated = NotificationService.mark_read(request.user, serializer.validated_data["ids"])
        return Response({"updated": updated})


class NotificationUnreadView(APIView):
    """읽지 않은 알림 수"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: NotificationUnreadSerializer}, tags=["알림"])
    def get(self, request):
        count = NotificationService.count_unread(request.user)
        return Response({"count": count})
