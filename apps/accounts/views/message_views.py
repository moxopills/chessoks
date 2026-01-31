from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.serializers import (
    DirectMessageCreateSerializer,
    DirectMessageSerializer,
    GuestbookCreateSerializer,
    GuestbookEntrySerializer,
)
from apps.accounts.services import MessageService
from apps.chess.utils import parse_int


class GuestbookView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: GuestbookEntrySerializer(many=True)}, tags=["유저"])
    def get(self, request, user_id: int):
        entries = MessageService.list_guestbook(user_id)
        return Response(GuestbookEntrySerializer(entries, many=True).data)

    @extend_schema(request=GuestbookCreateSerializer, responses={201: GuestbookEntrySerializer}, tags=["유저"])
    def post(self, request, user_id: int):
        serializer = GuestbookCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entry = MessageService.add_guestbook_entry(user_id, request.user, serializer.validated_data["message"])
        return Response(GuestbookEntrySerializer(entry).data, status=201)


class GuestbookDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(tags=["유저"])
    def delete(self, request, entry_id: int):
        MessageService.delete_guestbook_entry(entry_id, request.user)
        return Response({"message": "삭제되었습니다."})


class DirectMessageView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: DirectMessageSerializer(many=True)}, tags=["유저"])
    def get(self, request, user_id: int):
        limit = parse_int(request.query_params.get("limit"), default=50, min_value=1, max_value=200)
        offset = parse_int(request.query_params.get("offset"), default=0, min_value=0, max_value=10_000)
        total, messages = MessageService.list_messages(request.user, user_id, limit, offset)
        return Response({"count": total, "results": DirectMessageSerializer(messages, many=True).data})

    @extend_schema(request=DirectMessageCreateSerializer, responses={201: DirectMessageSerializer}, tags=["유저"])
    def post(self, request, user_id: int):
        serializer = DirectMessageCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message = MessageService.send_message(request.user, user_id, serializer.validated_data["message"])
        return Response(DirectMessageSerializer(message).data, status=201)
