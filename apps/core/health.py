"""헬스체크 엔드포인트"""

import logging

from django.core.cache import cache
from django.db import connection
from django.http import JsonResponse
from django.views import View

logger = logging.getLogger(__name__)


class HealthCheckView(View):
    """Liveness 체크 - 서버가 살아있는지 확인"""

    def get(self, request):
        return JsonResponse({"status": "ok"})


class ReadinessCheckView(View):
    """Readiness 체크 - 서비스 준비 상태 확인 (DB, Redis)"""

    def get(self, request):
        checks = {}
        is_ready = True

        # Database 체크
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            checks["database"] = "ok"
        except Exception as e:
            logger.error("Database health check failed: %s", e)
            checks["database"] = "error"
            is_ready = False

        # Redis/Cache 체크
        try:
            cache.set("health_check", "ok", 10)
            if cache.get("health_check") == "ok":
                checks["cache"] = "ok"
            else:
                checks["cache"] = "error"
                is_ready = False
        except Exception as e:
            logger.error("Cache health check failed: %s", e)
            checks["cache"] = "error"
            is_ready = False

        status_code = 200 if is_ready else 503
        return JsonResponse(
            {"status": "ready" if is_ready else "not_ready", "checks": checks},
            status=status_code,
        )
