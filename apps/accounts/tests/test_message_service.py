from datetime import timedelta

from django.utils import timezone

from rest_framework.exceptions import ValidationError

from apps.accounts.models import DirectMessage, DirectMessageThread, GuestbookEntry
from apps.accounts.services.message_service import MessageService
from apps.notifications.models import Notification

from .test_auth import BaseTestCase


class MessageServiceTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.create_verified_user(email="user@test.com", nickname="유저")
        self.other = self.create_verified_user(email="other@test.com", nickname="상대")

    def test_add_guestbook_entry_requires_message(self):
        with self.assertRaises(ValidationError):
            MessageService.add_guestbook_entry(self.other.id, self.user, "   ")

    def test_add_and_delete_guestbook_entry(self):
        entry = MessageService.add_guestbook_entry(self.other.id, self.user, "안녕")
        self.assertEqual(entry.profile_user_id, self.other.id)
        self.assertEqual(entry.author_id, self.user.id)
        self.assertEqual(entry.message, "안녕")

        with self.assertRaises(ValidationError):
            MessageService.delete_guestbook_entry(entry.id, self.other)

        MessageService.delete_guestbook_entry(entry.id, self.user)
        self.assertFalse(GuestbookEntry.objects.filter(pk=entry.id).exists())

    def test_send_message_creates_thread_and_notification(self):
        msg = MessageService.send_message(self.user, self.other.id, "테스트")
        thread = DirectMessageThread.objects.get(pk=msg.thread_id)
        self.assertIn(self.user.id, {thread.user1_id, thread.user2_id})
        self.assertIn(self.other.id, {thread.user1_id, thread.user2_id})
        self.assertEqual(msg.message, "테스트")
        self.assertTrue(
            Notification.objects.filter(
                user=self.other, type="direct_message", message__contains="테스트"
            ).exists()
        )

    def test_list_messages_no_count_returns_len(self):
        MessageService.send_message(self.user, self.other.id, "첫번째")
        MessageService.send_message(self.other, self.user.id, "두번째")
        total, items = MessageService.list_messages(
            self.user, self.other.id, limit=10, offset=0, no_count=True
        )
        self.assertEqual(total, len(items))
        self.assertEqual([m.message for m in items], ["두번째", "첫번째"])

    def test_list_threads_orders_by_last_message(self):
        third = self.create_verified_user(email="third@test.com", nickname="세번째")
        thread_a = MessageService.get_or_create_thread(self.user, self.other)
        thread_b = MessageService.get_or_create_thread(self.user, third)

        msg_a = DirectMessage.objects.create(thread=thread_a, sender=self.user, message="A")
        msg_b = DirectMessage.objects.create(thread=thread_b, sender=self.user, message="B")

        earlier = timezone.now() - timedelta(hours=2)
        later = timezone.now() - timedelta(hours=1)
        DirectMessage.objects.filter(pk=msg_a.pk).update(created_at=earlier)
        DirectMessage.objects.filter(pk=msg_b.pk).update(created_at=later)

        total, threads = MessageService.list_threads(self.user, limit=10, offset=0)
        self.assertEqual(total, 2)
        self.assertEqual(threads[0].id, thread_b.id)
        self.assertEqual(threads[0].last_message, "B")
