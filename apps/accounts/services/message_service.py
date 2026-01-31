from django.db import transaction

from rest_framework.exceptions import NotFound, ValidationError

from apps.accounts.models import DirectMessage, DirectMessageThread, GuestbookEntry, User


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

        if entry.author_id != user.id and entry.profile_user_id != user.id:
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
        user: User, other_id: int, limit: int, offset: int
    ) -> tuple[int, list[DirectMessage]]:
        other = User.objects.filter(pk=other_id).first()
        if not other:
            raise NotFound("유저 정보를 찾을 수 없습니다.")
        thread = MessageService.get_or_create_thread(user, other)
        queryset = DirectMessage.objects.select_related("sender", "sender__stats").filter(
            thread=thread
        )
        total = queryset.count()
        return total, list(queryset.order_by("created_at")[offset : offset + limit])

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
        return DirectMessage.objects.create(thread=thread, sender=user, message=message.strip())
