from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.accounts.forms import SignUpForm
from apps.accounts.models import UserStats

User = get_user_model()


class SignUpFormTestCase(TestCase):
    def _valid_data(self, **overrides):
        data = {
            "email": "test@example.com",
            "nickname": "테스터",
            "password1": "TestPass123!",
            "password2": "TestPass123!",
        }
        data.update(overrides)
        return data

    def test_save_creates_stats_and_normalizes_email(self):
        data = self._valid_data(email="Test@Example.COM")
        form = SignUpForm(data=data)

        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertTrue(UserStats.objects.filter(user=user).exists())
        self.assertEqual(user.email, User.objects.normalize_email(data["email"]))

    def test_duplicate_email_in_grace_period_rejected(self):
        user = User.objects.create_user(
            email="dup@test.com",
            nickname="기존닉",
            password="TestPass123!",
        )
        user.is_active = False
        user.scheduled_deletion_at = timezone.now() + timedelta(days=1)
        user.save(update_fields=["is_active", "scheduled_deletion_at"])

        form = SignUpForm(data=self._valid_data(email="dup@test.com", nickname="신규닉"))
        self.assertFalse(form.is_valid())
        self.assertIn("탈퇴 예약", form.errors["email"][0])

    def test_expired_deletion_email_allows_signup(self):
        user = User.objects.create_user(
            email="expired@test.com",
            nickname="만료닉",
            password="TestPass123!",
        )
        user.is_active = False
        user.scheduled_deletion_at = timezone.now() - timedelta(hours=1)
        user.save(update_fields=["is_active", "scheduled_deletion_at"])

        form = SignUpForm(
            data=self._valid_data(email="expired@test.com", nickname="신규닉2")
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertFalse(User.objects.filter(id=user.id).exists())

    def test_duplicate_nickname_in_grace_period_rejected(self):
        user = User.objects.create_user(
            email="old@test.com",
            nickname="중복닉",
            password="TestPass123!",
        )
        user.is_active = False
        user.scheduled_deletion_at = timezone.now() + timedelta(days=1)
        user.save(update_fields=["is_active", "scheduled_deletion_at"])

        form = SignUpForm(data=self._valid_data(email="new@test.com", nickname="중복닉"))
        self.assertFalse(form.is_valid())
        self.assertIn("탈퇴 예약", form.errors["nickname"][0])
