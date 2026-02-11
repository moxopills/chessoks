from django.core.cache import cache

from apps.accounts.tests.test_auth import BaseTestCase
from apps.adminpanel.models import Report
from apps.adminpanel.services import AdminPanelService


class AdminPanelServiceTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.create_verified_user(email="admin@test.com", nickname="관리자")
        self.other = self.create_verified_user(email="user@test.com", nickname="유저")

    def test_list_users_filters_and_orders(self):
        self.create_verified_user(email="alpha@test.com", nickname="알파")
        self.create_verified_user(email="beta@test.com", nickname="베타")

        total, users = AdminPanelService.list_users(query="알", limit=10, offset=0)
        self.assertEqual(total, 1)
        self.assertEqual(users[0].nickname, "알파")

        total, users = AdminPanelService.list_users(query=None, limit=2, offset=0)
        self.assertEqual(total, 4)
        self.assertEqual(len(users), 2)
        self.assertTrue(users[0].date_joined >= users[1].date_joined)

    def test_stats_cached_payload(self):
        cache.clear()
        initial = AdminPanelService.stats()
        self.create_verified_user(email="cache@test.com", nickname="캐시")
        cached = AdminPanelService.stats()
        self.assertEqual(initial["total_users"], cached["total_users"])

    def test_list_reports_filters_by_status(self):
        report_a = Report.objects.create(
            reporter=self.user, target=self.other, category="abuse", description="테스트"
        )
        report_b = Report.objects.create(
            reporter=self.user, target=self.other, category="spam", description="테스트"
        )
        report_b.mark_resolved(self.user, "resolved", "완료")

        total, pending = AdminPanelService.list_reports(status="pending", limit=10, offset=0)
        self.assertEqual(total, 1)
        self.assertEqual(pending[0].id, report_a.id)

        total, resolved = AdminPanelService.list_reports(status="resolved", limit=10, offset=0)
        self.assertEqual(total, 1)
        self.assertEqual(resolved[0].id, report_b.id)
