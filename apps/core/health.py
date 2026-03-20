"""헬스체크 엔드포인트"""

import logging

from django.http import JsonResponse
from django.views import View

from apps.core.ops import collect_health_snapshot, collect_runtime_metrics, summarize_health

logger = logging.getLogger(__name__)


class HealthCheckView(View):
    """Liveness 체크 - 서버가 살아있는지 확인"""

    def get(self, request):
        return JsonResponse({"status": "ok"})


class ReadinessCheckView(View):
    """Readiness 체크 - 서비스 준비 상태 확인."""

    def get(self, request):
        snapshot = collect_health_snapshot()
        is_ready, checks = summarize_health(snapshot)

        status_code = 200 if is_ready else 503
        return JsonResponse(
            {
                "status": "ready" if is_ready else "not_ready",
                "checks": checks,
                "details": snapshot,
            },
            status=status_code,
        )


class DetailedHealthCheckView(View):
    """세부 컴포넌트 상태 확인."""

    def get(self, request):
        snapshot = collect_health_snapshot()
        is_ready, checks = summarize_health(snapshot)
        return JsonResponse(
            {
                "status": "ok" if is_ready else "degraded",
                "checks": checks,
                "components": snapshot,
            },
            status=200 if is_ready else 503,
        )


class RuntimeMetricsView(View):
    """운영용 런타임 메트릭 스냅샷."""

    def get(self, request):
        return JsonResponse(
            {
                "status": "ok",
                "metrics": collect_runtime_metrics(),
            }
        )
