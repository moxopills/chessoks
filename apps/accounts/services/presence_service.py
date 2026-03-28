import logging
import threading
from time import time

from django.core.cache import cache

from apps.accounts.services.online_status_service import OnlineStatusService

logger = logging.getLogger(__name__)

_presence_list_lock = threading.Lock()


class PresenceService:
    TTL_SECONDS = OnlineStatusService.TTL_SECONDS
    LIST_TTL_SECONDS = 60 * 10

    STATUS_LOBBY = "lobby"
    STATUS_ROOM_WAITING = "room_waiting"
    STATUS_PLAYING = "playing"
    STATUS_COMPETITIVE = "competitive"
    STATUS_QUICK = "quick"
    STATUS_AI_PLAYING = "ai_playing"
    STATUS_SPECTATING = "spectating"
    STATUS_PUZZLE = "puzzle"
    STATUS_ONLINE = "online"
    STATUS_OFFLINE = "offline"

    STATUS_DEFINITIONS = {
        STATUS_ONLINE: {"priority": 10, "label": "온라인"},
        STATUS_LOBBY: {"priority": 60, "label": "로비에 있음"},
        STATUS_ROOM_WAITING: {"priority": 80, "label": "대기방에서 준비 중"},
        STATUS_PLAYING: {"priority": 100, "label": "대국 중"},
        STATUS_COMPETITIVE: {"priority": 100, "label": "경쟁전 대국 중"},
        STATUS_QUICK: {"priority": 100, "label": "빠른 대전 중"},
        STATUS_AI_PLAYING: {"priority": 95, "label": "AI 대전 중"},
        STATUS_SPECTATING: {"priority": 90, "label": "관전 중"},
        STATUS_PUZZLE: {"priority": 70, "label": "퍼즐 풀이 중"},
    }
    CLIENT_ALLOWED_STATUSES = {STATUS_ONLINE, STATUS_ROOM_WAITING, STATUS_PUZZLE}

    @staticmethod
    def _list_key(user_id: int) -> str:
        return f"user:presence:scopes:{user_id}"

    @staticmethod
    def _scope_key(user_id: int, scope: str) -> str:
        return f"user:presence:{user_id}:{scope}"

    @staticmethod
    def _normalize_scope(scope: str | None, status: str, room_id=None, game_id=None) -> str:
        if scope:
            return str(scope)
        parts = [status]
        if room_id:
            parts.append(f"room-{int(room_id)}")
        if game_id:
            parts.append(f"game-{int(game_id)}")
        return ":".join(parts)

    @staticmethod
    def build_scope(status: str, *, room_id=None, game_id=None) -> str:
        return PresenceService._normalize_scope(None, status, room_id=room_id, game_id=game_id)

    @staticmethod
    def _build_payload(status: str, *, room_id=None, game_id=None) -> dict:
        if status not in PresenceService.STATUS_DEFINITIONS:
            raise ValueError("지원하지 않는 상태입니다.")
        definition = PresenceService.STATUS_DEFINITIONS[status]
        return {
            "status": status,
            "label": definition["label"],
            "priority": definition["priority"],
            "updated_at": time(),
            "room_id": room_id,
            "game_id": game_id,
        }

    @staticmethod
    def set_presence(
        user_id: int,
        status: str,
        *,
        scope: str | None = None,
        room_id=None,
        game_id=None,
    ) -> str:
        scope_name = PresenceService._normalize_scope(
            scope, status, room_id=room_id, game_id=game_id
        )
        payload = PresenceService._build_payload(status, room_id=room_id, game_id=game_id)
        cache.set(
            PresenceService._scope_key(user_id, scope_name),
            payload,
            timeout=PresenceService.TTL_SECONDS,
        )
        OnlineStatusService.set_online(user_id)
        with _presence_list_lock:
            scopes = cache.get(PresenceService._list_key(user_id), [])
            if scope_name not in scopes:
                scopes.append(scope_name)
                cache.set(
                    PresenceService._list_key(user_id),
                    scopes,
                    timeout=PresenceService.LIST_TTL_SECONDS,
                )
        return scope_name

    @staticmethod
    def refresh_presence(
        user_id: int,
        *,
        scope: str | None = None,
        status: str | None = None,
        room_id=None,
        game_id=None,
    ) -> str | None:
        if scope is None and status is None:
            return None
        scope_name = PresenceService._normalize_scope(
            scope, status or PresenceService.STATUS_LOBBY, room_id=room_id, game_id=game_id
        )
        payload = cache.get(PresenceService._scope_key(user_id, scope_name))
        if payload is None:
            if status is None:
                return None
            return PresenceService.set_presence(
                user_id,
                status,
                scope=scope_name,
                room_id=room_id,
                game_id=game_id,
            )
        payload["updated_at"] = time()
        cache.set(
            PresenceService._scope_key(user_id, scope_name),
            payload,
            timeout=PresenceService.TTL_SECONDS,
        )
        OnlineStatusService.refresh(user_id)
        return scope_name

    @staticmethod
    def clear_presence(
        user_id: int,
        scope: str | None = None,
        *,
        status: str | None = None,
        room_id=None,
        game_id=None,
    ) -> None:
        if scope is None and status is None:
            return
        scope_name = PresenceService._normalize_scope(
            scope, status or PresenceService.STATUS_LOBBY, room_id=room_id, game_id=game_id
        )
        cache.delete(PresenceService._scope_key(user_id, scope_name))
        with _presence_list_lock:
            scopes = cache.get(PresenceService._list_key(user_id), [])
            if scope_name in scopes:
                scopes = [item for item in scopes if item != scope_name]
                cache.set(
                    PresenceService._list_key(user_id),
                    scopes,
                    timeout=PresenceService.LIST_TTL_SECONDS,
                )

    @staticmethod
    def clear_all(user_id: int) -> None:
        scopes = cache.get(PresenceService._list_key(user_id), [])
        for scope in scopes:
            cache.delete(PresenceService._scope_key(user_id, scope))
        cache.delete(PresenceService._list_key(user_id))

    @staticmethod
    def _resolve_best_payload(*, online: bool, payloads: list[dict]) -> dict:
        if not online:
            return {
                "online": False,
                "status": PresenceService.STATUS_OFFLINE,
                "status_label": "오프라인",
            }
        if not payloads:
            return {
                "online": True,
                "status": PresenceService.STATUS_ONLINE,
                "status_label": "온라인",
            }
        best = max(payloads, key=lambda item: (item.get("priority", 0), item.get("updated_at", 0)))
        return {
            "online": True,
            "status": best.get("status", PresenceService.STATUS_ONLINE),
            "status_label": best.get("label", "온라인"),
            "room_id": best.get("room_id"),
            "game_id": best.get("game_id"),
        }

    @staticmethod
    def bulk_presence(user_ids: list[int]) -> dict[int, dict]:
        if not user_ids:
            return {}

        online_map = OnlineStatusService.bulk_status(user_ids)
        list_key_map = {PresenceService._list_key(user_id): user_id for user_id in user_ids}
        scope_lists = cache.get_many(list_key_map.keys())

        scope_key_map: dict[str, tuple[int, str]] = {}
        for key, user_id in list_key_map.items():
            for scope in scope_lists.get(key, []) or []:
                scope_key_map[PresenceService._scope_key(user_id, scope)] = (user_id, scope)

        payload_map = cache.get_many(scope_key_map.keys()) if scope_key_map else {}
        stale_scopes: dict[int, list[str]] = {}
        grouped_payloads: dict[int, list[dict]] = {user_id: [] for user_id in user_ids}

        for cache_key, payload in payload_map.items():
            user_id, scope = scope_key_map[cache_key]
            if payload:
                grouped_payloads.setdefault(user_id, []).append(payload)
            else:
                stale_scopes.setdefault(user_id, []).append(scope)

        if stale_scopes:
            with _presence_list_lock:
                for user_id, stale in stale_scopes.items():
                    scopes = cache.get(PresenceService._list_key(user_id), []) or []
                    next_scopes = [scope for scope in scopes if scope not in stale]
                    cache.set(
                        PresenceService._list_key(user_id),
                        next_scopes,
                        timeout=PresenceService.LIST_TTL_SECONDS,
                    )

        return {
            user_id: PresenceService._resolve_best_payload(
                online=online_map.get(user_id, False),
                payloads=grouped_payloads.get(user_id, []),
            )
            for user_id in user_ids
        }

    @staticmethod
    def get_presence(user_id: int) -> dict:
        return PresenceService.bulk_presence([user_id]).get(
            user_id,
            {
                "online": False,
                "status": PresenceService.STATUS_OFFLINE,
                "status_label": "오프라인",
            },
        )
