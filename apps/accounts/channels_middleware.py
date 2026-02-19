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
            guest = await self._get_guest_session(token)
            if guest:
                scope["guest"] = guest

        return await super().__call__(scope, receive, send)

    @database_sync_to_async
    def _get_guest_session(self, token):
        from apps.accounts.models import GuestSession

        try:
            guest = GuestSession.objects.get(token=token)
            if not guest.is_expired:
                return {
                    "token": guest.token,
                    "nickname": guest.nickname,
                    "display_name": guest.display_name,
                }
        except GuestSession.DoesNotExist:
            pass
        return None
