from django.db import transaction
from django.db.models import OuterRef, Q, Subquery

from rest_framework.exceptions import NotFound, ValidationError

from apps.accounts.models import DirectMessage, DirectMessageThread, GuestbookEntry, User
from apps.notifications.services import NotificationService


class MessageService:
    @staticmethod
    def list_guestbook(profile_user_id: int) -> list[GuestbookEntry]:
        return list(
            GuestbookEntry.objects.select_related("author", "author__stats")
            .filter(profile_user_id=profile_user_id)
            .order_by("-created_at")
        )

    @staticmethod
    def add_guestbook_entry(profile_user_id: int, author: User, message: str) -> GuestbookEntry:
        if not message.strip():
            raise ValidationError({"message": "메시지를 입력해주세요."})
        return GuestbookEntry.objects.create(
            profile_user_id=profile_user_id,
            author=author,
            message=message.strip(),
        )

    @staticmethod
    def delete_guestbook_entry(entry_id: int, user: User) -> None:
        try:
            entry = GuestbookEntry.objects.select_related("profile_user", "author").get(pk=entry_id)
        except GuestbookEntry.DoesNotExist:
            raise NotFound("방명록을 찾을 수 없습니다.") from None

        if entry.author_id != user.id:
            raise ValidationError("삭제 권한이 없습니다.")
        entry.delete()

    @staticmethod
    def _normalize_pair(user: User, other: User) -> tuple[User, User]:
        return (user, other) if user.id < other.id else (other, user)

    @staticmethod
    @transaction.atomic
    def get_or_create_thread(user: User, other: User) -> DirectMessageThread:
        u1, u2 = MessageService._normalize_pair(user, other)
        thread, _ = DirectMessageThread.objects.get_or_create(user1=u1, user2=u2)
        return thread

    @staticmethod
    def list_messages(
        user: User, other_id: int, limit: int, offset: int, no_count: bool = False
    ) -> tuple[int, list[DirectMessage]]:
        other = User.objects.filter(pk=other_id).first()
        if not other:
            raise NotFound("유저 정보를 찾을 수 없습니다.")
        thread = MessageService.get_or_create_thread(user, other)
        queryset = DirectMessage.objects.select_related("sender", "sender__stats").filter(
            thread=thread
        )
        messages = list(queryset.order_by("-created_at")[offset : offset + limit])
        if no_count:
            return len(messages), messages
        total = queryset.count()
        return total, messages

    @staticmethod
    def list_threads(
        user: User, limit: int, offset: int, no_count: bool = False
    ) -> tuple[int, list[DirectMessageThread]]:
        last_message_qs = DirectMessage.objects.filter(thread=OuterRef("pk")).order_by(
            "-created_at"
        )
        queryset = (
            DirectMessageThread.objects.select_related(
                "user1", "user1__stats", "user2", "user2__stats"
            )
            .filter(Q(user1=user) | Q(user2=user))
            .annotate(
                last_message=Subquery(last_message_qs.values("message")[:1]),
                last_message_at=Subquery(last_message_qs.values("created_at")[:1]),
                last_sender_id=Subquery(last_message_qs.values("sender_id")[:1]),
            )
            .order_by("-last_message_at", "-updated_at")
        )
        threads = list(queryset[offset : offset + limit])
        if no_count:
            return len(threads), threads
        total = queryset.count()
        return total, threads

    @staticmethod
    @transaction.atomic
    def send_message(user: User, other_id: int, message: str) -> DirectMessage:
        other = User.objects.filter(pk=other_id).first()
        if not other:
            raise NotFound("유저 정보를 찾을 수 없습니다.")
        if user.is_suspended:
            raise ValidationError("정지된 계정입니다.")
        if user.is_muted:
            raise ValidationError("채팅이 제한된 계정입니다.")
        if not message.strip():
            raise ValidationError({"message": "메시지를 입력해주세요."})
        thread = MessageService.get_or_create_thread(user, other)
        message_obj = DirectMessage.objects.create(
            thread=thread, sender=user, message=message.strip()
        )
        DirectMessageThread.objects.filter(pk=thread.pk).update(updated_at=message_obj.created_at)
        NotificationService.create_notification(
            other,
            type="direct_message",
            title="1:1 채팅",
            message=f"{user.nickname}: {message_obj.message}",
            payload={"sender_id": user.id, "thread_id": thread.id},
        )
        return message_obj
