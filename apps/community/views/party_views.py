from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsAuthenticatedOrGuest
from apps.community.serializers import (
    PartyChatCreateSerializer,
    PartyChatMessageSerializer,
    PartyCreateSerializer,
    PartyDetailSerializer,
    PartyInviteCreateSerializer,
    PartyInviteRespondSerializer,
    PartyInviteSerializer,
    PartyLockSerializer,
    PartyMemberReadySerializer,
    PartySerializer,
    PartySlotSerializer,
)
from apps.community.services import PartyService
from apps.core.request import parse_bool_query


class PartyListCreateView(APIView):
    def get_permissions(self):
        return [AllowAny()] if self.request.method == "GET" else [IsAuthenticated()]

    def get(self, request):
        parties = PartyService.list_parties()
        no_count = parse_bool_query(request.query_params.get("no_count"))
        results = PartySerializer(parties, many=True).data
        return Response(
            {"count": len(results) if no_count else parties.count(), "results": results}
        )

    def post(self, request):
        serializer = PartyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        party = PartyService.create_party(request.user, **serializer.validated_data)
        return Response(PartyDetailSerializer(party).data, status=201)


class PartyDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, party_id: int):
        party = PartyService.get_party(party_id)
        return Response(PartyDetailSerializer(party).data)


class MyActivePartyView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    def get(self, request):
        summary = PartyService.get_active_party_summary(request.user)
        if not summary:
            return Response(
                {
                    "party_id": None,
                    "title": "",
                    "status": "",
                    "member_count": 0,
                    "leader_id": None,
                    "is_leader": False,
                    "can_invite": False,
                    "message": "참가 중인 활성 파티가 없습니다.",
                }
            )
        return Response(summary)


class PartyInviteView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, party_id: int):
        serializer = PartyInviteCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        invite = PartyService.invite_member(
            request.user,
            party_id,
            to_user_id=serializer.validated_data["user_id"],
        )
        return Response({"id": invite.id, "status": invite.status}, status=201)


class PartyInviteRespondView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    def post(self, request, invite_id: int):
        serializer = PartyInviteRespondSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        invite = PartyService.respond_invite(
            request.user, invite_id, accept=serializer.validated_data["accept"]
        )
        return Response({"id": invite.id, "status": invite.status})


class PartyInviteListView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    def get(self, request):
        invites = PartyService.list_pending_invites(request.user)
        no_count = parse_bool_query(request.query_params.get("no_count"))
        results = PartyInviteSerializer(invites, many=True).data
        return Response(
            {"count": len(results) if no_count else invites.count(), "results": results}
        )


class PartyTransferLeaderView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, party_id: int, user_id: int):
        party = PartyService.transfer_leader(request.user, party_id, user_id=user_id)
        return Response({"party_id": party.id, "leader_id": party.leader_id})


class PartyLeaveView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    def post(self, request, party_id: int):
        party = PartyService.leave_party(request.user, party_id)
        return Response({"party_id": party.id if party else None, "closed": party is None})


class PartyCloseView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, party_id: int):
        PartyService.close_party(request.user, party_id)
        return Response({"party_id": party_id, "closed": True})


class PartyReadyView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    def post(self, request, party_id: int):
        serializer = PartyMemberReadySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        member = PartyService.set_ready(
            request.user,
            party_id,
            ready=serializer.validated_data["ready"],
        )
        return Response({"user_id": member.user_id, "is_ready": member.is_ready})


class PartyLineupLockView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, party_id: int):
        serializer = PartyLockSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data["locked"]:
            party = PartyService.lock_lineup(request.user, party_id)
        else:
            party = PartyService.unlock_lineup(request.user, party_id)
        return Response(
            {"party_id": party.id, "lineup_locked": party.lineup_locked, "status": party.status}
        )


class PartySlotView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, party_id: int):
        serializer = PartySlotSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        member = PartyService.assign_slot(
            request.user,
            party_id,
            user_id=serializer.validated_data["user_id"],
            slot=serializer.validated_data["slot"],
        )
        return Response({"user_id": member.user_id, "slot": member.slot})


class PartyChatView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    def get(self, request, party_id: int):
        messages = PartyService.list_chat_messages(request.user, party_id)
        return Response(
            {
                "count": len(messages),
                "results": PartyChatMessageSerializer(messages, many=True).data,
            }
        )

    def post(self, request, party_id: int):
        serializer = PartyChatCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message = PartyService.post_chat_message(
            request.user, party_id, content=serializer.validated_data["content"]
        )
        return Response(PartyChatMessageSerializer(message).data, status=201)


class PartyKickView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, party_id: int, user_id: int):
        PartyService.remove_member(request.user, party_id, user_id=user_id)
        return Response({"status": "removed", "user_id": user_id})
