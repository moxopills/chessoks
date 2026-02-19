"""WebSocket 미들웨어 for Channels"""

from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware


class GuestTokenMiddleware(BaseMiddleware):
    """WebSocket 연결에서 게스트 토큰을 처리하는 미들웨어"""

    async def __call__(self, scope, receive, send):
        # 게스트 정보 초기화
        scope["guest"] = None

        # 인증된 유저가 아닌 경우에만 게스트 토큰 확인
        user = scope.get("user")
        if user and user.is_authenticated:
            return await super().__call__(scope, receive, send)

        # 쿼리 스트링에서 게스트 토큰 추출
        query_string = scope.get("query_string", b"").decode()
        token = None

        for param in query_string.split("&"):
            if param.startswith("guest_token="):
                token = param.split("=", 1)[1]
                break

        if token:
            guest_data, guest_user = await self._get_guest_session_and_user(token)
            if guest_data:
                scope["guest"] = guest_data
                # 게스트 User가 있으면 scope["user"]로 설정 (게임 참여용)
                if guest_user:
                    scope["user"] = guest_user

        return await super().__call__(scope, receive, send)

    @database_sync_to_async
    def _get_guest_session_and_user(self, token):
        from apps.accounts.models import GuestSession

        try:
            guest = GuestSession.objects.select_related("user").get(token=token)
            if not guest.is_expired:
                guest_data = {
                    "token": guest.token,
                    "nickname": guest.nickname,
                    "display_name": guest.display_name,
                }
                # 게스트 User가 있으면 반환
                guest_user = guest.user if guest.user_id else None
                return guest_data, guest_user
        except GuestSession.DoesNotExist:
            pass
        return None, None
