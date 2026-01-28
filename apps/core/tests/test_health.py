"""헬스체크 테스트"""

from django.test import TestCase


class HealthCheckTestCase(TestCase):
    def test_liveness_check(self):
        """Liveness 체크 테스트"""
        response = self.client.get("/api/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_readiness_check(self):
        """Readiness 체크 테스트"""
        response = self.client.get("/api/health/ready/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ready")
        self.assertEqual(data["checks"]["database"], "ok")
        self.assertEqual(data["checks"]["cache"], "ok")
