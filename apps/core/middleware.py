"""운영 미들웨어"""

import logging
import time
import uuid

logger = logging.getLogger(__name__)


class RequestIDMiddleware:
    """요청 ID 추적 미들웨어 - 모든 요청에 고유 ID 부여"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
        request.request_id = request_id

        response = self.get_response(request)
        response["X-Request-ID"] = request_id
        return response


class RequestTimingMiddleware:
    """요청 처리 시간 측정 미들웨어"""

    SLOW_REQUEST_THRESHOLD_MS = 1000  # 1초 이상이면 경고

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start_time = time.perf_counter()

        response = self.get_response(request)

        duration_ms = (time.perf_counter() - start_time) * 1000
        response["X-Response-Time"] = f"{duration_ms:.2f}ms"

        # 느린 요청 로깅
        if duration_ms > self.SLOW_REQUEST_THRESHOLD_MS:
            request_id = getattr(request, "request_id", "-")
            logger.warning(
                "Slow request: %s %s took %.2fms [%s]",
                request.method,
                request.path,
                duration_ms,
                request_id,
            )

        return response
