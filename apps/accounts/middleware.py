from __future__ import annotations

import math

from django.contrib import messages
from django.contrib.auth import logout
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils import timezone


def _suspension_remaining_text(suspended_until) -> str:
    if not suspended_until:
        return ""
    delta = suspended_until - timezone.now()
    seconds = max(0, int(delta.total_seconds()))
    days = math.ceil(seconds / 86400) if seconds else 0
    if days >= 1:
        return f"{days}일 남았습니다."
    hours = max(1, math.ceil(seconds / 3600))
    return f"{hours}시간 남았습니다."


class SuspendedUserLogoutMiddleware:
    """정지 계정 접근 시 즉시 로그아웃 처리."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user and user.is_authenticated and user.is_suspended:
            remaining = _suspension_remaining_text(user.suspended_until)
            message = "정지된 계정입니다."
            if remaining:
                message = f"{message} {remaining}"

            logout(request)

            if request.path.startswith("/api/"):
                return JsonResponse(
                    {"error": {"code": "account_suspended", "message": message}},
                    status=403,
                )

            messages.error(request, message)
            return redirect("/login/")

        return self.get_response(request)


class GuestSessionMiddleware:
    """게스트 세션 처리 미들웨어"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.guest = None

        # 로그인 유저는 게스트 처리 안 함
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            return self.get_response(request)

        # 게스트 토큰 확인
        token = request.headers.get("X-Guest-Token") or request.COOKIES.get("guest_token")

        if token:
            from apps.accounts.models import GuestSession

            try:
                guest = GuestSession.objects.get(token=token)
                if not guest.is_expired:
                    request.guest = guest
                    # 활동 시간 업데이트
                    guest.save(update_fields=["last_activity"])
            except GuestSession.DoesNotExist:
                pass

        return self.get_response(request)
