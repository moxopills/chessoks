"""게임 초대 API 뷰"""

import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.chess.serializers import GameInviteCreateSerializer
from apps.chess.services.invite_service import InviteService
from apps.core.throttling import InviteActionThrottle

logger = logging.getLogger(__name__)


class GameInviteView(APIView):
    """게임 초대 전송"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [InviteActionThrottle]

    def post(self, request):
        serializer = GameInviteCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target_user_id = serializer.validated_data["user_id"]
        time_limit = serializer.validated_data["time_limit"]
        room_id = serializer.validated_data.get("room_id")

        try:
            invite = InviteService.send_invite(
                from_user=request.user,
                to_user_id=target_user_id,
                time_limit=time_limit,
                room_id=room_id,
            )
            return Response(
                {
                    "status": "sent",
                    "invite_id": invite.id,
                    "message": "초대를 전송했습니다.",
                }
            )
        except Exception as e:
            logger.warning("Game invite failed: %s", e)
            message = getattr(e, "detail", "초대 처리 중 오류가 발생했습니다.")
            return Response({"detail": message}, status=status.HTTP_400_BAD_REQUEST)


class GameInviteAcceptView(APIView):
    """게임 초대 수락"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [InviteActionThrottle]

    def post(self, request, invite_id: int):
        try:
            room = InviteService.accept_invite(
                invite_id=invite_id,
                user=request.user,
            )
            return Response(
                {
                    "status": "accepted",
                    "room_id": room.id,
                    "message": "초대를 수락했습니다.",
                }
            )
        except Exception as e:
            logger.warning("Game invite accept failed: %s", e)
            message = getattr(e, "detail", "초대 수락 처리 중 오류가 발생했습니다.")
            return Response({"detail": message}, status=status.HTTP_400_BAD_REQUEST)


class GameInviteDeclineView(APIView):
    """게임 초대 거절"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [InviteActionThrottle]

    def post(self, request, invite_id: int):
        try:
            InviteService.decline_invite(
                invite_id=invite_id,
                user=request.user,
            )
            return Response(
                {
                    "status": "declined",
                    "message": "초대를 거절했습니다.",
                }
            )
        except Exception as e:
            logger.warning("Game invite decline failed: %s", e)
            message = getattr(e, "detail", "초대 거절 처리 중 오류가 발생했습니다.")
            return Response({"detail": message}, status=status.HTTP_400_BAD_REQUEST)
