"""게스트 세션 관련 뷰"""

import re
import secrets

from django.utils import timezone

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.accounts.models import GuestSession, User


class GuestSessionView(APIView):
    """게스트 세션 생성"""

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "guest"

    def post(self, request):
        nickname = request.data.get("nickname", "").strip()

        # 닉네임 검증
        if not nickname or len(nickname) < 2 or len(nickname) > 10:
            return Response(
                {"error": {"message": "닉네임은 2~10자여야 합니다."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not re.match(r"^[가-힣a-zA-Z0-9]+$", nickname):
            return Response(
                {"error": {"message": "닉네임은 한글, 영문, 숫자만 사용 가능합니다."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 금칙어 체크 (간단한 목록)
        forbidden = ["관리자", "운영자", "admin", "root", "system"]
        if nickname.lower() in forbidden:
            return Response(
                {"error": {"message": "사용할 수 없는 닉네임입니다."}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 중복 체크 및 처리
        final_nickname = self._get_unique_nickname(nickname)

        # 세션 생성
        guest = GuestSession.objects.create(
            nickname=final_nickname, ip_address=self._get_client_ip(request)
        )

        return Response(
            {
                "token": guest.token,
                "nickname": guest.nickname,
                "display_name": guest.display_name,
                "expires_at": guest.expires_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )

    def _get_unique_nickname(self, nickname):
        """중복 시 랜덤 접미사 추가"""
        # 기존 회원 닉네임 체크
        if User.objects.filter(nickname=nickname).exists():
            suffix = secrets.token_hex(2)
            return f"{nickname}_{suffix}"

        # 활성 게스트 닉네임 체크
        if GuestSession.objects.filter(nickname=nickname, expires_at__gt=timezone.now()).exists():
            suffix = secrets.token_hex(2)
            return f"{nickname}_{suffix}"

        return nickname

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")


class GuestMeView(APIView):
    """현재 게스트 정보"""

    permission_classes = [AllowAny]

    def get(self, request):
        if not hasattr(request, "guest") or not request.guest:
            return Response(
                {"error": {"message": "게스트 세션이 없습니다."}},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        guest = request.guest
        return Response(
            {
                "nickname": guest.nickname,
                "display_name": guest.display_name,
                "expires_at": guest.expires_at.isoformat(),
                "is_guest": True,
            }
        )

    def delete(self, request):
        """게스트 세션 종료"""
        if hasattr(request, "guest") and request.guest:
            guest = request.guest
            # 연결된 게스트 User도 삭제
            if guest.user_id:
                try:
                    guest.user.delete()
                except Exception:
                    pass
            guest.delete()
            return Response({"message": "게스트 세션이 종료되었습니다."})

        return Response(
            {"error": {"message": "게스트 세션이 없습니다."}},
            status=status.HTTP_401_UNAUTHORIZED,
        )
