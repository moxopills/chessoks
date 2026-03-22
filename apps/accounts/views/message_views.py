from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.serializers import (
    DirectMessageCreateSerializer,
    DirectMessageSerializer,
    DirectMessageThreadSerializer,
    GuestbookCreateSerializer,
    GuestbookEntrySerializer,
)
from apps.accounts.services import MessageService
from apps.chess.utils import check_profanity, get_profanity_warning
from apps.core.request import parse_pagination_query
from apps.core.throttling import MessageActionThrottle


class GuestbookView(APIView):
    permission_classes = [IsAuthenticated]

    def get_throttles(self):
        if self.request.method == "POST":
            return [MessageActionThrottle()]
        return super().get_throttles()

    @extend_schema(responses={200: GuestbookEntrySerializer(many=True)}, tags=["유저"])
    def get(self, request, user_id: int):
        entries = MessageService.list_guestbook(user_id)
        return Response(GuestbookEntrySerializer(entries, many=True).data)

    @extend_schema(
        request=GuestbookCreateSerializer, responses={201: GuestbookEntrySerializer}, tags=["유저"]
    )
    def post(self, request, user_id: int):
        serializer = GuestbookCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message = serializer.validated_data["message"]
        if check_profanity(message):
            return Response({"detail": get_profanity_warning()}, status=400)
        entry = MessageService.add_guestbook_entry(user_id, request.user, message)
        return Response(GuestbookEntrySerializer(entry).data, status=201)


class GuestbookDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(tags=["유저"])
    def delete(self, request, entry_id: int):
        MessageService.delete_guestbook_entry(entry_id, request.user)
        return Response({"message": "삭제되었습니다."})


class DirectMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def get_throttles(self):
        if self.request.method == "POST":
            return [MessageActionThrottle()]
        return super().get_throttles()

    @extend_schema(responses={200: DirectMessageSerializer(many=True)}, tags=["유저"])
    def get(self, request, user_id: int):
        limit, offset, no_count = parse_pagination_query(
            request.query_params,
            default_limit=50,
            max_limit=200,
        )
        total, messages = MessageService.list_messages(
            request.user, user_id, limit, offset, no_count=no_count
        )
        return Response(
            {"count": total, "results": DirectMessageSerializer(messages, many=True).data}
        )

    @extend_schema(
        request=DirectMessageCreateSerializer,
        responses={201: DirectMessageSerializer},
        tags=["유저"],
    )
    def post(self, request, user_id: int):
        serializer = DirectMessageCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        content = serializer.validated_data["message"]
        if check_profanity(content):
            return Response({"detail": get_profanity_warning()}, status=400)
        message = MessageService.send_message(request.user, user_id, content)
        return Response(DirectMessageSerializer(message).data, status=201)


class DirectMessageThreadView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: DirectMessageThreadSerializer(many=True)}, tags=["유저"])
    def get(self, request):
        limit, offset, no_count = parse_pagination_query(
            request.query_params,
            default_limit=50,
            max_limit=200,
        )
        total, threads = MessageService.list_threads(request.user, limit, offset, no_count=no_count)
        results = []
        for thread in threads:
            other_user = thread.user2 if thread.user1_id == request.user.id else thread.user1
            results.append(
                {
                    "id": thread.id,
                    "other_user": other_user,
                    "last_message": getattr(thread, "last_message", None) or "",
                    "last_message_at": getattr(thread, "last_message_at", None),
                }
            )
        return Response(
            {"count": total, "results": DirectMessageThreadSerializer(results, many=True).data}
        )
