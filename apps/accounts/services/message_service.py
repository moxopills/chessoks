from django.db import transaction
from django.db.models import OuterRef, Q, Subquery

from rest_framework.exceptions import NotFound, ValidationError

from apps.accounts.models import DirectMessage, DirectMessageThread, GuestbookEntry, User
from apps.notifications.services import NotificationService


class MessageService:
    THREAD_USER_SELECT_RELATED = (
        "user1",
        "user1__stats",
        "user1__stats__selected_board_skin",
        "user1__stats__selected_piece_skin",
        "user2",
        "user2__stats",
        "user2__stats__selected_board_skin",
        "user2__stats__selected_piece_skin",
    )

    MESSAGE_SELECT_RELATED = (
        "sender",
        "sender__stats",
        "sender__stats__selected_board_skin",
        "sender__stats__selected_piece_skin",
    )

    @staticmethod
    def list_guestbook(profile_user_id: int) -> list[GuestbookEntry]:
        return list(
            GuestbookEntry.objects.select_related(
                "author",
                "author__stats",
                "author__stats__selected_board_skin",
                "author__stats__selected_piece_skin",
            )
            .filter(profile_user_id=profile_user_id)
            .order_by("-created_at")
            .only(
                "id",
                "message",
                "created_at",
                "author__id",
                "author__nickname",
                "author__avatar_url",
                "author__bio",
                "author__created_at",
                "author__updated_at",
                "author__stats__rating",
                "author__stats__games_played",
                "author__stats__games_won",
                "author__stats__games_lost",
                "author__stats__games_draw",
                "author__stats__competitive_games_played",
                "author__stats__style_points",
                "author__stats__nickname_color",
                "author__stats__profile_border",
                "author__stats__season_title",
                "author__stats__profile_card_frame",
                "author__stats__owned_season_titles",
                "author__stats__owned_profile_card_frames",
                "author__stats__owned_nickname_colors",
                "author__stats__owned_profile_borders",
                "author__stats__selected_board_skin__css_class",
                "author__stats__selected_piece_skin__css_class",
            )
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
    def get_thread(user: User, other: User) -> DirectMessageThread | None:
        u1, u2 = MessageService._normalize_pair(user, other)
        return DirectMessageThread.objects.filter(user1=u1, user2=u2).first()

    @staticmethod
    def list_messages(
        user: User, other_id: int, limit: int, offset: int, no_count: bool = False
    ) -> tuple[int, list[DirectMessage]]:
        other = User.objects.only("id").filter(pk=other_id).first()
        if not other:
            raise NotFound("유저 정보를 찾을 수 없습니다.")
        thread = MessageService.get_thread(user, other)
        if thread is None:
            return 0, []
        queryset = DirectMessage.objects.select_related(
            *MessageService.MESSAGE_SELECT_RELATED
        ).filter(thread=thread)
        queryset = queryset.only(
            "id",
            "message",
            "created_at",
            "sender__id",
            "sender__nickname",
            "sender__avatar_url",
            "sender__bio",
            "sender__created_at",
            "sender__updated_at",
            "sender__stats__rating",
            "sender__stats__games_played",
            "sender__stats__games_won",
            "sender__stats__games_lost",
            "sender__stats__games_draw",
            "sender__stats__competitive_games_played",
            "sender__stats__style_points",
            "sender__stats__nickname_color",
            "sender__stats__profile_border",
            "sender__stats__season_title",
            "sender__stats__profile_card_frame",
            "sender__stats__owned_season_titles",
            "sender__stats__owned_profile_card_frames",
            "sender__stats__owned_nickname_colors",
            "sender__stats__owned_profile_borders",
            "sender__stats__selected_board_skin__css_class",
            "sender__stats__selected_piece_skin__css_class",
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
            DirectMessageThread.objects.select_related(*MessageService.THREAD_USER_SELECT_RELATED)
            .filter(Q(user1=user) | Q(user2=user))
            .annotate(
                last_message=Subquery(last_message_qs.values("message")[:1]),
                last_message_at=Subquery(last_message_qs.values("created_at")[:1]),
                last_sender_id=Subquery(last_message_qs.values("sender_id")[:1]),
            )
            .order_by("-last_message_at", "-updated_at")
        )
        queryset = queryset.only(
            "id",
            "updated_at",
            "user1__id",
            "user1__nickname",
            "user1__avatar_url",
            "user1__bio",
            "user1__created_at",
            "user1__updated_at",
            "user1__stats__rating",
            "user1__stats__games_played",
            "user1__stats__games_won",
            "user1__stats__games_lost",
            "user1__stats__games_draw",
            "user1__stats__competitive_games_played",
            "user1__stats__style_points",
            "user1__stats__nickname_color",
            "user1__stats__profile_border",
            "user1__stats__season_title",
            "user1__stats__profile_card_frame",
            "user1__stats__owned_season_titles",
            "user1__stats__owned_profile_card_frames",
            "user1__stats__owned_nickname_colors",
            "user1__stats__owned_profile_borders",
            "user1__stats__selected_board_skin__css_class",
            "user1__stats__selected_piece_skin__css_class",
            "user2__id",
            "user2__nickname",
            "user2__avatar_url",
            "user2__bio",
            "user2__created_at",
            "user2__updated_at",
            "user2__stats__rating",
            "user2__stats__games_played",
            "user2__stats__games_won",
            "user2__stats__games_lost",
            "user2__stats__games_draw",
            "user2__stats__competitive_games_played",
            "user2__stats__style_points",
            "user2__stats__nickname_color",
            "user2__stats__profile_border",
            "user2__stats__season_title",
            "user2__stats__profile_card_frame",
            "user2__stats__owned_season_titles",
            "user2__stats__owned_profile_card_frames",
            "user2__stats__owned_nickname_colors",
            "user2__stats__owned_profile_borders",
            "user2__stats__selected_board_skin__css_class",
            "user2__stats__selected_piece_skin__css_class",
        )
        threads = list(queryset[offset : offset + limit])
        if no_count:
            return len(threads), threads
        total = queryset.count()
        return total, threads

    @staticmethod
    @transaction.atomic
    def send_message(user: User, other_id: int, message: str) -> DirectMessage:
        other = User.objects.only("id").filter(pk=other_id).first()
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
