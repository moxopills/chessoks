"""게임 초대 서비스"""

import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from rest_framework.exceptions import ValidationError

from apps.accounts.models import User
from apps.chess.models import GameInvite, Room
from apps.notifications.services import NotificationService

logger = logging.getLogger(__name__)


class InviteService:
    """게임 초대 서비스"""

    INVITE_EXPIRE_MINUTES = 2  # 초대 만료 시간

    @staticmethod
    def send_invite(from_user, to_user_id: int, time_limit: int = 10) -> GameInvite:
        """게임 초대 전송"""
        if from_user.id == to_user_id:
            raise ValidationError("자기 자신에게 초대를 보낼 수 없습니다.")

        to_user = User.objects.filter(id=to_user_id).first()
        if not to_user:
            raise ValidationError("존재하지 않는 사용자입니다.")

        # 이미 대기 중인 초대가 있는지 확인
        pending = GameInvite.objects.filter(
            from_user=from_user,
            to_user=to_user,
            status="pending",
            created_at__gte=timezone.now() - timedelta(minutes=InviteService.INVITE_EXPIRE_MINUTES),
        ).first()
        if pending:
            raise ValidationError("이미 초대를 보냈습니다. 잠시 후 다시 시도해주세요.")

        # 초대 생성
        invite = GameInvite.objects.create(
            from_user=from_user,
            to_user=to_user,
            time_limit=time_limit,
            status="pending",
        )

        # 상대에게 알림 전송
        NotificationService.create_notification(
            user=to_user,
            type="game_invite",
            title="게임 초대",
            message=f"{from_user.nickname}님이 게임 초대를 보냈습니다.",
            payload={
                "invite_id": invite.id,
                "from_user_id": from_user.id,
                "from_user_nickname": from_user.nickname,
                "from_user_avatar": from_user.avatar_url or "",
                "from_user_rating": from_user.stats.rating if hasattr(from_user, "stats") else 1500,
                "time_limit": time_limit,
            },
            push=True,
        )

        logger.info("Game invite sent: %s -> %s", from_user.nickname, to_user.nickname)
        return invite

    @staticmethod
    def accept_invite(invite_id: int, user) -> Room:
        """게임 초대 수락"""
        with transaction.atomic():
            invite = GameInvite.objects.select_for_update().filter(id=invite_id).first()
            if not invite:
                raise ValidationError("초대를 찾을 수 없습니다.")

            if invite.to_user_id != user.id:
                raise ValidationError("본인에게 온 초대만 수락할 수 있습니다.")

            if invite.status != "pending":
                raise ValidationError("이미 처리된 초대입니다.")

            # 만료 확인
            expire_time = invite.created_at + timedelta(minutes=InviteService.INVITE_EXPIRE_MINUTES)
            if timezone.now() > expire_time:
                invite.status = "expired"
                invite.save(update_fields=["status"])
                raise ValidationError("만료된 초대입니다.")

            # 방 생성 (초대자가 호스트)
            room = Room.objects.create(
                room_type="custom",
                title=f"{invite.from_user.nickname}의 초대 게임",
                host=invite.from_user,
                guest=invite.to_user,
                time_limit=invite.time_limit,
                increment_seconds=5,
                status="waiting",
            )

            invite.status = "accepted"
            invite.room = room
            invite.responded_at = timezone.now()
            invite.save(update_fields=["status", "room", "responded_at"])

            # 초대자에게 알림
            NotificationService.create_notification(
                user=invite.from_user,
                type="room_event",
                title="초대 수락",
                message=f"{user.nickname}님이 게임 초대를 수락했습니다.",
                payload={
                    "room_id": room.id,
                    "user_id": user.id,
                    "user_nickname": user.nickname,
                },
                push=True,
            )

            logger.info("Game invite accepted: %s <- %s", invite.from_user.nickname, user.nickname)
            return room

    @staticmethod
    def decline_invite(invite_id: int, user) -> None:
        """게임 초대 거절"""
        with transaction.atomic():
            invite = GameInvite.objects.select_for_update().filter(id=invite_id).first()
            if not invite:
                raise ValidationError("초대를 찾을 수 없습니다.")

            if invite.to_user_id != user.id:
                raise ValidationError("본인에게 온 초대만 거절할 수 있습니다.")

            if invite.status != "pending":
                raise ValidationError("이미 처리된 초대입니다.")

            invite.status = "declined"
            invite.responded_at = timezone.now()
            invite.save(update_fields=["status", "responded_at"])

            # 초대자에게 알림
            NotificationService.create_notification(
                user=invite.from_user,
                type="game_invite_declined",
                title="초대 거절",
                message=f"{user.nickname}님이 게임 초대를 거절했습니다.",
                payload={
                    "user_id": user.id,
                    "user_nickname": user.nickname,
                },
                push=True,
            )

            logger.info("Game invite declined: %s <- %s", invite.from_user.nickname, user.nickname)
