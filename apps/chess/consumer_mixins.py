from django.core.cache import cache

from channels.db import database_sync_to_async

from apps.accounts.services import OnlineStatusService, PresenceService


class OnlineStatusMixin:
    """온라인 상태 관리 Mixin (Heartbeat 방식)"""

    def _get_user_id(self):
        user = self.scope.get("user")
        return user.id if user and user.is_authenticated else None

    async def _handle_heartbeat(self, content=None):
        """heartbeat 처리 - TTL 갱신"""
        user_id = self._get_user_id()
        if user_id:
            OnlineStatusService.refresh(user_id)
            await self._refresh_user_presence()
            await self.send_json({"type": "heartbeat_ack"})

    async def _set_user_online(self):
        user_id = self._get_user_id()
        if user_id:
            OnlineStatusService.set_online(user_id)

    async def _set_user_presence(self, status: str, *, scope: str, room_id=None, game_id=None):
        user_id = self._get_user_id()
        if not user_id:
            return
        await self._set_presence_sync(
            user_id,
            status,
            scope=scope,
            room_id=room_id,
            game_id=game_id,
        )
        self._presence_scope = scope
        self._presence_status = status
        self._presence_room_id = room_id
        self._presence_game_id = game_id

    async def _refresh_user_presence(self):
        user_id = self._get_user_id()
        if not user_id or not getattr(self, "_presence_scope", None):
            return
        await self._refresh_presence_sync(
            user_id,
            scope=self._presence_scope,
            status=getattr(self, "_presence_status", None),
            room_id=getattr(self, "_presence_room_id", None),
            game_id=getattr(self, "_presence_game_id", None),
        )

    async def _clear_user_presence(self):
        user_id = self._get_user_id()
        scope = getattr(self, "_presence_scope", None)
        if not user_id or not scope:
            return
        await self._clear_presence_sync(
            user_id,
            scope=scope,
            status=getattr(self, "_presence_status", None),
            room_id=getattr(self, "_presence_room_id", None),
            game_id=getattr(self, "_presence_game_id", None),
        )

    @database_sync_to_async
    def _set_presence_sync(self, user_id, status, *, scope, room_id=None, game_id=None):
        PresenceService.set_presence(
            user_id,
            status,
            scope=scope,
            room_id=room_id,
            game_id=game_id,
        )

    @database_sync_to_async
    def _refresh_presence_sync(self, user_id, *, scope, status=None, room_id=None, game_id=None):
        PresenceService.refresh_presence(
            user_id,
            scope=scope,
            status=status,
            room_id=room_id,
            game_id=game_id,
        )

    @database_sync_to_async
    def _clear_presence_sync(self, user_id, *, scope, status=None, room_id=None, game_id=None):
        PresenceService.clear_presence(
            user_id,
            scope=scope,
            status=status,
            room_id=room_id,
            game_id=game_id,
        )


class WebSocketRateLimitMixin:
    async def _check_ws_rate_limit(
        self,
        scope_name: str,
        *,
        limit: int,
        window_seconds: int,
        key_suffix: str = "",
    ) -> bool:
        allowed = await self._consume_ws_rate_limit(
            scope_name,
            limit=limit,
            window_seconds=window_seconds,
            key_suffix=key_suffix,
        )
        if not allowed:
            await self.send_json(
                {"type": "error", "message": "요청이 너무 빠릅니다. 잠시 후 다시 시도해주세요."}
            )
        return allowed

    @database_sync_to_async
    def _consume_ws_rate_limit(
        self,
        scope_name: str,
        *,
        limit: int,
        window_seconds: int,
        key_suffix: str = "",
    ) -> bool:
        user = self.scope.get("user")
        user_key = (
            user.id if user and getattr(user, "is_authenticated", False) else self.channel_name
        )
        group_key = getattr(self, "room_id", "lobby")
        key = f"wsrl:{scope_name}:{group_key}:{user_key}:{key_suffix}"
        if cache.add(key, 1, timeout=window_seconds):
            return True
        try:
            current = cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout=window_seconds)
            return True
        return current <= limit
