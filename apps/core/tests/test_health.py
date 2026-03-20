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
        self.assertIn("details", data)
        self.assertIn("channels", data["checks"])

    def test_detailed_health_check(self):
        """세부 컴포넌트 헬스체크 테스트"""
        response = self.client.get("/api/health/details/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("components", data)
        self.assertIn("database", data["components"])
        self.assertIn("celery", data["components"])

    def test_runtime_metrics(self):
        """운영 메트릭 스냅샷 테스트"""
        response = self.client.get("/api/health/metrics/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("metrics", data)
        self.assertIn("rooms", data["metrics"])
        self.assertIn("notifications", data["metrics"])
