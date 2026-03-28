import logging
import threading

from django.core.cache import cache

logger = logging.getLogger(__name__)

# 온라인 목록 수정을 위한 간단한 락 (단일 프로세스 환경용)
_online_list_lock = threading.Lock()


class OnlineStatusService:
    """
    온라인 상태 관리 서비스 (Heartbeat 방식)

    - 클라이언트는 주기적으로 heartbeat를 보내 TTL을 갱신
    - 모든 연결이 끊기면 TTL 만료 후 자동으로 오프라인 처리
    - 다중 탭/창 문제 해결: 각 탭이 heartbeat를 보내므로 하나만 닫아도 온라인 유지
    """

    TTL_SECONDS = 60
    HEARTBEAT_INTERVAL = 30  # 클라이언트 heartbeat 권장 주기
    LIST_TTL_SECONDS = 600

    @staticmethod
    def _key(user_id: int) -> str:
        return f"user:online:{user_id}"

    @staticmethod
    def _list_key() -> str:
        return "user:online:list"

    @staticmethod
    def _get_list() -> list[int]:
        return cache.get(OnlineStatusService._list_key(), [])

    @staticmethod
    def _set_list(user_ids: list[int]) -> None:
        cache.set(
            OnlineStatusService._list_key(), user_ids, timeout=OnlineStatusService.LIST_TTL_SECONDS
        )

    @staticmethod
    def set_online(user_id: int) -> None:
        """온라인 상태 설정 (TTL 갱신)"""
        cache.set(OnlineStatusService._key(user_id), True, timeout=OnlineStatusService.TTL_SECONDS)
        with _online_list_lock:
            user_ids = OnlineStatusService._get_list()
            if user_id not in user_ids:
                user_ids.append(user_id)
                OnlineStatusService._set_list(user_ids)

    @staticmethod
    def refresh(user_id: int) -> None:
        """heartbeat - TTL 갱신 (set_online과 동일)"""
        OnlineStatusService.set_online(user_id)

    @staticmethod
    def set_offline(user_id: int) -> None:
        """명시적 오프라인 (로그아웃 등)"""
        cache.delete(OnlineStatusService._key(user_id))
        from apps.accounts.services.presence_service import PresenceService

        PresenceService.clear_all(user_id)
        with _online_list_lock:
            user_ids = OnlineStatusService._get_list()
            if user_id in user_ids:
                user_ids = [uid for uid in user_ids if uid != user_id]
                OnlineStatusService._set_list(user_ids)

    @staticmethod
    def is_online(user_id: int) -> bool:
        return cache.get(OnlineStatusService._key(user_id)) is True

    @staticmethod
    def bulk_status(user_ids: list[int]) -> dict[int, bool]:
        keys = {OnlineStatusService._key(user_id): user_id for user_id in user_ids}
        cached = cache.get_many(keys.keys())
        status = dict.fromkeys(user_ids, False)
        for key in cached.keys():
            status[keys[key]] = True
        return status

    @staticmethod
    def list_online_ids() -> list[int]:
        user_ids = OnlineStatusService._get_list()
        if not user_ids:
            return []
        status = OnlineStatusService.bulk_status(user_ids)
        online_ids = [user_id for user_id in user_ids if status.get(user_id)]
        if len(online_ids) != len(user_ids):
            OnlineStatusService._set_list(online_ids)
        return online_ids
