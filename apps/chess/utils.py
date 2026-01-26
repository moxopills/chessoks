"""Chess 앱 공통 유틸리티"""

import random

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


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
    async_to_sync(channel_layer.group_send)(
        "chess_lobby", {"type": "broadcast", "payload": payload}
    )


def broadcast_room_removed(room_id: int) -> None:
    """방 삭제 브로드캐스트"""
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = {"type": "room_removed", "room_id": room_id}
    async_to_sync(channel_layer.group_send)(
        "chess_lobby", {"type": "broadcast", "payload": payload}
    )
