"""운영 미들웨어"""

import logging
import time
import uuid

from django.conf import settings

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


class SecurityHeadersMiddleware:
    """응답 보안 헤더 강화 + 민감 API 캐시 금지."""

    NO_STORE_PREFIXES = (
        "/api/accounts/login/",
        "/api/accounts/logout/",
        "/api/accounts/password/",
        "/api/accounts/email-change/",
        "/api/accounts/signup-email/",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if not getattr(settings, "SECURITY_HEADERS_ENABLED", True):
            return response

        # 기본 보안 헤더(없을 때만 주입)
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("X-Frame-Options", getattr(settings, "X_FRAME_OPTIONS", "DENY"))
        response.setdefault(
            "Referrer-Policy", getattr(settings, "SECURE_REFERRER_POLICY", "same-origin")
        )
        response.setdefault(
            "Cross-Origin-Resource-Policy",
            getattr(settings, "SECURE_CROSS_ORIGIN_RESOURCE_POLICY", "same-origin"),
        )
        response.setdefault(
            "Permissions-Policy",
            getattr(
                settings,
                "SECURE_PERMISSIONS_POLICY",
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
            ),
        )
        if getattr(settings, "SECURE_CONTENT_SECURITY_POLICY_ENABLED", False):
            response.setdefault(
                "Content-Security-Policy",
                getattr(settings, "SECURE_CONTENT_SECURITY_POLICY", ""),
            )

        # 인증/계정 관련 민감 응답은 브라우저 캐시 금지
        path = request.path or ""
        if any(path.startswith(prefix) for prefix in self.NO_STORE_PREFIXES):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response["Pragma"] = "no-cache"
            response["Expires"] = "0"

        return response
