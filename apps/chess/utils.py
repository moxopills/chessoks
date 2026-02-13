"""Chess 앱 공통 유틸리티"""

import logging
import random
import re

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from korcen import korcen

logger = logging.getLogger(__name__)


def parse_int(value, default: int, min_value: int, max_value: int) -> int:
    """쿼리 파라미터를 정수로 변환 (범위 제한 포함)"""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_value, min(parsed, max_value))


def assign_colors(host, guest):
    """호스트/게스트에게 랜덤으로 흑/백 배정"""
    if random.choice([True, False]):
        return host, guest
    return guest, host


def broadcast_room_update(room) -> None:
    """방 업데이트 브로드캐스트"""
    from apps.chess.serializers import RoomSerializer

    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = {"type": "room_update", "room": RoomSerializer(room).data}
    try:
        async_to_sync(channel_layer.group_send)(
            "chess_lobby", {"type": "broadcast", "payload": payload}
        )
    except Exception as exc:
        logger.error("broadcast_room_update failed room=%s: %s", room.id, exc)


def broadcast_room_state(room) -> None:
    """방 대기실/관전용 업데이트 브로드캐스트"""
    from apps.chess.serializers import RoomSerializer

    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = {"type": "room_update", "room": RoomSerializer(room).data}
    try:
        async_to_sync(channel_layer.group_send)(
            f"chess_room_{room.id}", {"type": "broadcast", "payload": payload}
        )
        async_to_sync(channel_layer.group_send)(
            f"chess_room_{room.id}_spectators", {"type": "broadcast", "payload": payload}
        )
    except Exception as exc:
        logger.error("broadcast_room_state failed room=%s: %s", room.id, exc)


def broadcast_room_removed(room_id: int) -> None:
    """방 삭제 브로드캐스트"""
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = {"type": "room_removed", "room_id": room_id}
    try:
        async_to_sync(channel_layer.group_send)(
            "chess_lobby", {"type": "broadcast", "payload": payload}
        )
    except Exception as exc:
        logger.error("broadcast_room_removed failed room_id=%s: %s", room_id, exc)


def broadcast_spectator_event(room_id: int, user, action: str) -> None:
    """관전자 입장/퇴장 이벤트 브로드캐스트"""
    from apps.chess.serializers import BaseUserSerializer

    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = {
        "type": "spectator_event",
        "action": action,
        "user": BaseUserSerializer(user).data,
    }
    try:
        async_to_sync(channel_layer.group_send)(
            f"chess_room_{room_id}", {"type": "broadcast", "payload": payload}
        )
        async_to_sync(channel_layer.group_send)(
            f"chess_room_{room_id}_spectators", {"type": "broadcast", "payload": payload}
        )
    except Exception as exc:
        logger.error("broadcast_spectator_event failed room_id=%s: %s", room_id, exc)


_EXTRA_PROFANITY_PATTERNS = re.compile(
    r"(씨발|씨팔|씨바|씨빨|ㅆ발|ㅆ팔|ㅆ바|ㅆㅂ|시발|시팔|시바|시빨|ㅅㅂ|병신|ㅄ|좆|존나|개새끼|새끼|fuck|shit)",
    re.IGNORECASE,
)

# ===== 욕설 필터링 =====


def check_profanity(text: str) -> bool:
    """텍스트에 욕설이 포함되어 있는지 확인"""
    if not text:
        return False
    try:
        if korcen.check(text):
            return True
    except Exception:
        pass
    normalized = re.sub(r"[\s\W_]+", "", text, flags=re.UNICODE)
    return bool(_EXTRA_PROFANITY_PATTERNS.search(normalized))


def filter_profanity(text: str, mask_char: str = "*") -> str:
    """텍스트의 욕설을 마스킹 처리"""
    if not text:
        return text
    return korcen.highlight_profanity(text, highlight_char=mask_char)


def get_profanity_warning() -> str:
    """욕설 감지 시 경고 메시지 반환"""
    return "욕설이 포함된 메시지는 전송할 수 없습니다."
