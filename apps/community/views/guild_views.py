from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.community.serializers import (
    GuildAuditLogSerializer,
    GuildAvatarUpdateSerializer,
    GuildChatCreateSerializer,
    GuildChatMessageSerializer,
    GuildCreateSerializer,
    GuildDetailSerializer,
    GuildJoinRequestCreateSerializer,
    GuildJoinRequestReviewSerializer,
    GuildJoinRequestSerializer,
    GuildMemberRoleSerializer,
    GuildSerializer,
)
from apps.community.services import GuildService


class GuildListCreateView(APIView):
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_permissions(self):
        return [AllowAny()] if self.request.method == "GET" else [IsAuthenticated()]

    def get(self, request):
        guilds = GuildService.list_guilds()
        return Response(
            {"count": guilds.count(), "results": GuildSerializer(guilds, many=True).data}
        )

    def post(self, request):
        serializer = GuildCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        guild = GuildService.create_guild(request.user, **serializer.validated_data)
        return Response(GuildDetailSerializer(guild).data, status=201)


class GuildDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, guild_id: int):
        guild = GuildService.get_guild(guild_id)
        return Response(GuildDetailSerializer(guild).data)


class GuildJoinRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, guild_id: int):
        join_requests = GuildService.list_join_requests(request.user, guild_id)
        return Response(
            {
                "count": join_requests.count(),
                "results": GuildJoinRequestSerializer(join_requests, many=True).data,
            }
        )

    def post(self, request, guild_id: int):
        serializer = GuildJoinRequestCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        join_request = GuildService.request_join(
            request.user, guild_id, message=serializer.validated_data.get("message", "")
        )
        return Response({"id": join_request.id, "status": join_request.status}, status=201)


class GuildJoinRequestReviewView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, request_id: int):
        serializer = GuildJoinRequestReviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        join_request = GuildService.review_join_request(
            request.user,
            request_id,
            approve=serializer.validated_data["approve"],
        )
        return Response({"id": join_request.id, "status": join_request.status})


class GuildNoticeUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, guild_id: int):
        guild = GuildService.update_notice(
            request.user,
            guild_id,
            notice=request.data.get("notice", ""),
        )
        return Response({"notice": guild.notice})


class GuildAvatarUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def patch(self, request, guild_id: int):
        serializer = GuildAvatarUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        guild = GuildService.update_avatar(
            request.user,
            guild_id,
            file=serializer.validated_data["avatar"],
        )
        return Response({"avatar_url": guild.avatar_url})


class GuildMemberRoleUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, guild_id: int, user_id: int):
        serializer = GuildMemberRoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        member = GuildService.update_member_role(
            request.user,
            guild_id,
            user_id,
            role=serializer.validated_data["role"],
        )
        return Response({"user_id": member.user_id, "role": member.role})


class GuildTransferLeaderView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, guild_id: int, user_id: int):
        guild = GuildService.transfer_leadership(request.user, guild_id, member_user_id=user_id)
        return Response({"guild_id": guild.id, "owner_id": guild.owner_id})


class GuildLeaveView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, guild_id: int):
        GuildService.leave_guild(request.user, guild_id)
        return Response({"status": "left"})


class GuildMemberKickView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, guild_id: int, user_id: int):
        GuildService.remove_member(request.user, guild_id, member_user_id=user_id)
        return Response({"status": "removed", "user_id": user_id})


class GuildAuditLogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, guild_id: int):
        logs = GuildService.list_audit_logs(request.user, guild_id)
        return Response(
            {"count": len(logs), "results": GuildAuditLogSerializer(logs, many=True).data}
        )


class GuildChatView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, guild_id: int):
        messages = GuildService.list_chat_messages(request.user, guild_id)
        return Response(
            {
                "count": len(messages),
                "results": GuildChatMessageSerializer(messages, many=True).data,
            }
        )

    def post(self, request, guild_id: int):
        serializer = GuildChatCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message = GuildService.post_chat_message(
            request.user, guild_id, content=serializer.validated_data["content"]
        )
        return Response(GuildChatMessageSerializer(message).data, status=201)
