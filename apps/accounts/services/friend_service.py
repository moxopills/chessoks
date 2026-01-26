from django.db import transaction
from django.shortcuts import get_object_or_404

from rest_framework.exceptions import ValidationError

from apps.accounts.models import Friend, FriendRequest, User
from apps.notifications.services import NotificationService


class FriendService:
    """친구 기능 서비스"""

    @staticmethod
    @transaction.atomic
    def send_request(from_user, to_user_id: int) -> dict:
        to_user = get_object_or_404(User, pk=to_user_id)
        if to_user == from_user:
            raise ValidationError({"user_id": ["자기 자신에게 친구 요청을 보낼 수 없습니다."]})

        if Friend.objects.filter(user=from_user, friend=to_user).exists():
            raise ValidationError({"user_id": ["이미 친구 상태입니다."]})

        if FriendRequest.objects.filter(from_user=from_user, to_user=to_user).exists():
            raise ValidationError({"user_id": ["이미 친구 요청을 보냈습니다."]})

        reverse_request = FriendRequest.objects.filter(
            from_user=to_user, to_user=from_user
        ).first()
        if reverse_request:
            FriendService._create_friendship(from_user, to_user)
            reverse_request.delete()
            NotificationService.create_notification(
                user=to_user,
                type="friend_accept",
                title="친구 수락",
                message=f"{from_user.nickname}님이 친구 요청을 수락했습니다.",
                payload={"user_id": from_user.id},
            )
            return {"status": "accepted"}

        request = FriendRequest.objects.create(from_user=from_user, to_user=to_user)
        NotificationService.create_notification(
            user=to_user,
            type="friend_request",
            title="친구 요청",
            message=f"{from_user.nickname}님이 친구 요청을 보냈습니다.",
            payload={"user_id": from_user.id, "request_id": request.id},
        )
        return {"status": "requested", "request_id": request.id}

    @staticmethod
    @transaction.atomic
    def accept_request(user, request_id: int) -> None:
        request = get_object_or_404(FriendRequest, pk=request_id, to_user=user)
        FriendService._create_friendship(request.from_user, request.to_user)
        request.delete()
        NotificationService.create_notification(
            user=request.from_user,
            type="friend_accept",
            title="친구 수락",
            message=f"{user.nickname}님이 친구 요청을 수락했습니다.",
            payload={"user_id": user.id},
        )

    @staticmethod
    @transaction.atomic
    def reject_request(user, request_id: int) -> None:
        request = get_object_or_404(FriendRequest, pk=request_id, to_user=user)
        request.delete()

    @staticmethod
    def list_friends(user) -> list[Friend]:
        return list(Friend.objects.filter(user=user).select_related("friend", "friend__stats"))

    @staticmethod
    def list_requests(user, *, direction: str) -> list[FriendRequest]:
        if direction == "outgoing":
            return list(
                FriendRequest.objects.filter(from_user=user).select_related("to_user__stats")
            )
        return list(
            FriendRequest.objects.filter(to_user=user).select_related("from_user__stats")
        )

    @staticmethod
    def _create_friendship(user, friend) -> None:
        Friend.objects.get_or_create(user=user, friend=friend)
        Friend.objects.get_or_create(user=friend, friend=user)
